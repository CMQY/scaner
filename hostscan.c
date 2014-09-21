#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#define TIME_OUT 5
#define THREAD_COUNT 20
#define K 1024
#define BUFFERSIZE 72

static unsigned char send_buff[BUFFERSIZE];
static unsigned char recv_buff[2*K];
static struct sockaddr_in dest;
static pid_t pid=0;
static int alive=0;
static short packet_send=0;
static short packet_recv=0;
static char dest_str[80];
static int rawsocket=0;

static int sum=0;
jmp_buf jmpbuff;
static void handle_sigint2(int signo)
{
	longjmp(jmpbuff,1);
}
typedef struct {
	int start_port;
	int end_port;
}port_struct;

port_struct port1,port2[20];
static int open_port_list[1000]={0};


static struct timeval tv_begin,tv_end,tv_interval;
typedef struct _raw_packet{
        struct timeval tv_begin;
        struct timeval tv_end;
        short seq;
        int flag;
}raw_packet;

static raw_packet rawpacket[128];


static raw_packet *raw_findpacket(int seq)
{
	int i=0;
	raw_packet *found=NULL;
	if(seq==-1)
	{
		for(i=0;i<128;i++)
		{
			if(rawpacket[i].flag==0)
			{
				found=&rawpacket[i];	//标志在send时置位
				break;
			}
		}
	}
	else if(seq>=0)
	{
		for(i=0;i<128;i++)
		{
			if(rawpacket[i].seq==seq)
			{
				found=&rawpacket;
				break;
			}
		}
	}
	return found;
}

static void* checkport(void *arg)
{
	int rawsocket2;
	int ret=0;
	struct sockaddr_in dest2;
	struct timeval tv;
	fd_set set;
	unsigned long ul=1;
	int error=-1,len;
	bzero(&dest2,sizeof(dest2));
	dest2.sin_family=AF_INET;
	memcpy((char *)&dest2.sin_addr,&dest.sin_addr,sizeof(dest.sin_addr));
	int i=((port_struct *)arg)->start_port;
	for(;i<((port_struct *)arg)->end_port;i++){
		if((rawsocket2=socket(AF_INET,SOCK_STREAM,0))<0)
			perror("socket");
		dest2.sin_port=htons(i);
		ul=1;
		error=-1;
		ret=0;
		len=sizeof(int);
		ioctl(rawsocket2,FIONBIO,&ul);	//设置非阻塞模式
		if(connect(rawsocket2,(struct sockaddr *)&dest2,sizeof(struct sockaddr))!=0)
		{
			if(errno==EINPROGRESS){
				tv.tv_sec=TIME_OUT;
				tv.tv_usec=0;
				FD_ZERO(&set);
				FD_SET(rawsocket2,&set);
				if(select(rawsocket2+1,NULL,&set,NULL,&tv)>0)
				{
					getsockopt(rawsocket2,SOL_SOCKET,SO_ERROR,&error,(socklen_t *)&len);
					if(error==0)
						ret=1;
				}
			}
			else
				ret=0;
		}
		else
			ret=1;
		if(ret>0)
		{
			open_port_list[i]=1;
			close(rawsocket2);
		}
	//	else
	//		printf("port %d is not open\n",i);
	}
}

static struct timeval timev_sub(struct timeval end,struct timeval begin)
{
		struct timeval tv;
		tv.tv_sec=end.tv_sec-begin.tv_sec;
		tv.tv_usec=end.tv_usec-begin.tv_usec;
		if(tv.tv_usec<0)
		{
			tv.tv_usec+=1000000;
			tv.tv_sec--;
		}
	return tv;
}


static unsigned short rcr16_cksum(unsigned char *data,int len)
{
	int sum=0;
	int odd =len &0x01;
	while(len & 0xFFFE){
		sum+=*(unsigned short *)data;
		data+=2;
		len-=2;
	}
	if(odd){
		unsigned short tmp=((*data)<<8)&0xFF00;
		sum+=tmp;
	}
	sum=(sum>>16)+(sum&0xFFFF);
	sum+=(sum>>16);
	return ~sum;
}

static void icmp_pack(struct icmp*icmph,int seq,struct timeval *tv,int length)
{	//seq 为发送包的序号，用于识别返回包，tv用于记录时间
	unsigned char i=0;
	icmph->icmp_type=ICMP_ECHO;
	icmph->icmp_code=0;
	icmph->icmp_cksum=0;	//先占位
	icmph->icmp_seq=seq;
	icmph->icmp_id=pid&0xffff;
	for(i=0;i<length;i++)
		icmph->icmp_data[i]=i;	//gcc不会让这里溢出
	icmph->icmp_cksum=rcr16_cksum((unsigned char *)icmph,length);
}
static int icmp_unpack(char *buf,int len)
{
	int i,iphdrlen;
	struct ip *ip=NULL;
	struct icmp *icmp=NULL;
	int rtt;
	
	ip=(struct ip*)buf;
	iphdrlen=ip->ip_hl*4;
	icmp=(struct icmp*)(buf+iphdrlen);
	len-=iphdrlen;
	
	if(len<8)
	{
		printf("ICMP packets\'s length is less than 8\n");
		return -1;
	}
	
	if((icmp->icmp_type==ICMP_ECHOREPLY)&&(icmp->icmp_id==pid))
	{	
		struct timeval tv_internel,tv_recv,tv_send;
		raw_packet *packet=raw_findpacket(icmp->icmp_seq);
		if(packet==NULL)
			return -1;
		packet->flag=0;		//完成标记方便统计
		tv_send=packet->tv_begin;
		gettimeofday(&tv_recv,NULL);
		tv_internel=timev_sub(tv_recv,tv_send);
		rtt=tv_internel.tv_sec*1000+tv_internel.tv_usec/1000;
		printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%d ms\n",len,
			inet_ntoa(ip->ip_src),icmp->icmp_seq,ip->ip_ttl,rtt);
		packet_recv ++;
	}
	else
	{
		return -1;
	}
}
		

static void* raw_send(void *argv)
{
	gettimeofday(&tv_begin,NULL);
	while(alive)
	{
		int size=0;
		struct timeval tv;
		gettimeofday(&tv,NULL);
		raw_packet *packet=raw_findpacket(-1);
		if(packet)
		{
			packet->seq=packet_send;
			packet->flag=1;
			gettimeofday(&packet->tv_begin,NULL);
		}
		icmp_pack((struct icmp*)send_buff,packet_send,&tv,64);
		size =sendto(rawsocket,send_buff,64,0,(struct sockaddr *)&dest,
				sizeof(dest));
		if(size<0)
		{
			perror("sendto error");
			continue;
		}
		
		packet_send++;
		sleep(1);
	}
}

static void *raw_recv(void *argv)
{
	struct timeval tv;
	tv.tv_usec=200;
	tv.tv_sec=0;
	fd_set readfd;
	while(alive)
	{
		int ret=0;
		FD_ZERO(&readfd);
		FD_SET(rawsocket,&readfd);
		ret=select(rawsocket+1,&readfd,NULL,NULL,&tv);
		switch(ret)
		{
			case -1:		//错误发生
				break;
			case 0:
				break;		//超时
			default:
			{
				int size=recv(rawsocket,recv_buff,sizeof(recv_buff),0);
				if(errno==EINTR)
				{
					perror("recvfrom error");
					continue;
				}
				ret=icmp_unpack(recv_buff,size);
				if(ret==-1)
				{
					continue;
				}
			}
			break;
		}
	}
}



static void handle_sigint(int signo)
{
	alive=0;
	gettimeofday(&tv_end,NULL);
	tv_interval=timev_sub(tv_end,tv_begin);
	return ;
}



static void statistics(void)
{
	long time=(tv_interval.tv_sec*1000)+(tv_interval.tv_usec/1000);
	printf("\n---%s statistics ---\n",dest_str);
	printf("%d packets transmitted, %d received,%d%c packet loss,time %d ms\n",
		packet_send,packet_recv,(packet_send-packet_recv)*100/packet_send,'%',
			time);
}


int main(int argc,char * argv[])
{
	struct hostent *host=NULL;
	struct protoent *protocol=NULL;
	char protoname[]="icmp";
	unsigned long inaddr=1;
	int size=128*K;	
	if(argc<3)
	{
		printf("usage: scaner <option> <host> [startport [endport]]\n");
		return -1;
	}
	if(strcmp(argv[1],"-P")==0)
	{
	protocol=getprotobyname(protoname);
	if(protocol==NULL)
	{
		perror("getprotobyname");
		return -1;
	}

	memcpy(dest_str,argv[2],strlen(argv[2])+1);
	memset(rawpacket,0,sizeof(raw_packet)*128);

	rawsocket=socket(AF_INET,SOCK_RAW,protocol->p_proto);
	if(rawsocket<0)
	{
		perror("socket");
		return -1;
	}
	
	pid=getuid();
	//增大接收缓冲区
	setsockopt(rawsocket,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size));
	bzero(&dest,sizeof(dest));
	
	dest.sin_family=AF_INET;
	inaddr=inet_addr(argv[2]);
	if(inaddr==INADDR_NONE)
	{
		host=gethostbyname(argv[2]);
		if(host==NULL)
		{
			perror("gethostbyname");
			return -1;
		}
		memcpy((char *)&dest.sin_addr,host->h_addr,host->h_length);
	}
	else
	{
		memcpy((char *)&dest.sin_addr,&inaddr,sizeof(inaddr));
	}
	inaddr=dest.sin_addr.s_addr;
	printf("PING %s (%d.%d.%d.%d) 56(84) bytes of data.\n",
		dest_str,(inaddr&0x000000FF)>>0,(inaddr&0x0000FF00)>>8,
			(inaddr&0x00FF0000)>>16,(inaddr&0xFF000000)>>24);
	signal(SIGINT,handle_sigint);
	
	alive=1;
	pthread_t send_id,recv_id;
	int err=0;
	err=pthread_create(&send_id,NULL,raw_send,NULL);
	if(err<0)
	{
		return -1;
	}
	err=pthread_create(&recv_id,NULL,raw_recv,NULL);
	if(err<0)
	{
		return -1;
	}
	
	pthread_join(send_id,NULL);
	pthread_join(recv_id,NULL);
	
	close(rawsocket);
	statistics();
	return 0;
	}
	else if(strcmp(argv[1],"-T")==0)
	{
    // 	struct hostent *host=NULL;
	int i=0;
	unsigned long inaddr=1;
	int startport=1,endport=1000;
	if(argc>=4)
	{
		if(argv[3]!=NULL)
			sscanf(argv[3],"%d",&startport);
		if(argc>4)
		{
			if(argv[4]!=NULL)
				sscanf(argv[4],"%d",&endport);
		}
	}
	if(startport<1||endport>1000){
		printf("port error\n");
		return -1;
	}
	memcpy(dest_str,argv[2],strlen(argv[2])+1);
	
	bzero(&dest,sizeof(dest));
//	dest.sin_family=AF_INET;
	inaddr=inet_addr(argv[2]);
	if(inaddr==INADDR_NONE)
	{
		host=gethostbyname(argv[2]);
		if(host==NULL)
		{
			perror("gethostbyname");
			return -1;
		}
		memcpy((char *)&dest.sin_addr,host->h_addr,host->h_length);
	}
	else{
		memcpy((char *)&dest.sin_addr,&inaddr,sizeof(inaddr));
	}
	
	inaddr=dest.sin_addr.s_addr;
	printf("intersting in %s %d.%d.%d.%d port %d to %d \nnow scaning...\n",dest_str,
			(inaddr&0x000000FF)>>0,(inaddr&0x0000FF00)>>8,(inaddr&0x00FF0000)>>16,
			(inaddr&0xFF000000)>>24,startport,endport);
	signal(SIGINT,handle_sigint2);
	memset(&open_port_list,0,sizeof(open_port_list));
	if(setjmp(jmpbuff)==0)
	{
		int i=endport-startport;
		if(i<THREAD_COUNT)
		{
			pthread_t t;
			port1.start_port=startport;
			port1.end_port=endport;
			if(pthread_create(&t,NULL,checkport,&port1)<0)
				return -1;
			pthread_join(t,NULL);
		}
		else
		{
			pthread_t t3[THREAD_COUNT];
			int j=0,k=i/THREAD_COUNT;
			for(;j<THREAD_COUNT;j++)
			{
				if(j<THREAD_COUNT-1){
					port2[j].start_port=startport+j*k;
					port2[j].end_port=startport+(j+1)*k;
				}
				else{
					port2[j].start_port=startport+j*k;
					port2[j].end_port=endport;
				}
				if(pthread_create(&t3[j],NULL,checkport,&port2[j])<0)
					return -1;
			}
			for(j=0;j<THREAD_COUNT;j++)
				pthread_join(t3[j],NULL);
		}
	}

	int l=0;
	for(;l<1000;l++)
	{
		if(open_port_list[l]==1)
		{
			sum++;
			printf("port %d is open\n",l);
		}
	}
	printf("totally %d ports open\n",sum);
	return 0;
	}
	else
	{
		printf("nuknown option\n");
	}
}

