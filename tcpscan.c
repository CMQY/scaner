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
#include <sys/ioctl.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <setjmp.h>
#include <pthread.h>
#define TIME_OUT 5
#define THREAD_COUNT 20
static struct sockaddr_in dest;
static char dest_str[80];
static int sum=0;
jmp_buf jmpbuff;
static void handle_sigint(int signo)
{
	longjmp(jmpbuff,1);
}
typedef struct {
	int start_port;
	int end_port;
}port_struct;

port_struct port1,port2[20];
static int open_port_list[1000]={0};
static void* checkport(void *arg)
{
	int rawsocket;
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
		if((rawsocket=socket(AF_INET,SOCK_STREAM,0))<0)
			perror("socket");
		dest2.sin_port=htons(i);
		ul=1;
		error=-1;
		ret=0;
		len=sizeof(int);
		ioctl(rawsocket,FIONBIO,&ul);	//设置非阻塞模式
		if(connect(rawsocket,(struct sockaddr *)&dest2,sizeof(struct sockaddr))!=0)
		{
			if(errno==EINPROGRESS){
				tv.tv_sec=TIME_OUT;
				tv.tv_usec=0;
				FD_ZERO(&set);
				FD_SET(rawsocket,&set);
				if(select(rawsocket+1,NULL,&set,NULL,&tv)>0)
				{
					getsockopt(rawsocket,SOL_SOCKET,SO_ERROR,&error,(socklen_t *)&len);
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
			close(rawsocket);
		}
	//	else
	//		printf("port %d is not open\n",i);
	}
}
		
int main(int argc,char * argv[])
{	
	struct hostent *host=NULL;
	int i=0;
	unsigned long inaddr=1;
	if(argc<2)
		printf("check the fucking help");
	int startport=1,endport=1000;
	if(argc>=3)
	{
		if(argv[2]!=NULL)
			sscanf(argv[2],"%d",&startport);
		if(argc>3)
		{
			if(argv[3]!=NULL)
				sscanf(argv[3],"%d",&endport);
		}
	}
	if(startport<1||endport>1000){
		printf("port error\n");
		return -1;
	}
	memcpy(dest_str,argv[1],strlen(argv[1])+1);
	
	bzero(&dest,sizeof(dest));
//	dest.sin_family=AF_INET;
	inaddr=inet_addr(argv[1]);
	if(inaddr==INADDR_NONE)
	{
		host=gethostbyname(argv[1]);
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
	printf("intersting in %s %d.%d.%d.%d port %d to %d now scaning...\n",dest_str,
			(inaddr&0x000000FF)>>0,(inaddr&0x0000FF00)>>8,(inaddr&0x00FF0000)>>16,
			(inaddr&0xFF000000)>>24,startport,endport);
	signal(SIGINT,handle_sigint);
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
