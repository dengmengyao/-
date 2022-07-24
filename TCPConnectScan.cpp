#include "TCPConnectScan.h"

void* ThreadTCPconnectHost(void* param)
{
	struct TCPConHostThrParam *p;
	string HostIP;
	unsigned HostPort;
    int ConSock;
	struct sockaddr_in HostAddr; 
	int ret;

    p=(struct TCPConHostThrParam*)param;
    HostIP = p->HostIP;
	HostPort = p->HostPort;
    
	//创建socket连接
	ConSock = socket(AF_INET,SOCK_STREAM,0);
	if(ConSock < 0)
	{
		pthread_mutex_lock(&TCPConPrintlocker);
		cout<<"Create TCP connect Socket failed! "<<endl;
		pthread_mutex_unlock(&TCPConPrintlocker);
	}
    
    //设置链接地址
	memset(&HostAddr,0,sizeof(HostAddr));
	HostAddr.sin_family = AF_INET;
	HostAddr.sin_addr.s_addr = inet_addr(&HostIP[0]);
	HostAddr.sin_port = htons(HostPort);

	//socket连接
    ret = connect(ConSock,(struct sockaddr*)&HostAddr,sizeof(HostAddr));
	if(ret==-1)
	{
		pthread_mutex_lock(&TCPConPrintlocker);
	    cout<<"Host: "<<HostIP<<" Port: "<<HostPort<<" closed ! "<<endl;
		pthread_mutex_unlock(&TCPConPrintlocker);
	}
	else
	{
		pthread_mutex_lock(&TCPConPrintlocker);
        cout<<"Host: "<<HostIP<<" Port: "<<HostPort<<" open ! "<<endl;
		pthread_mutex_unlock(&TCPConPrintlocker);
	}
	//退出进程
	delete p;
    close(ConSock);
	pthread_mutex_lock(&TCPConScanlocker);
        TCPConThrdNum--;
	pthread_mutex_unlock(&TCPConScanlocker);

}

void* ThreadTCPconnectScan(void* param)
{
    struct TCPConThrParam *p;

	string HostIP;
	unsigned BeginPort,EndPort,TempPort;
	
	pthread_t subThreadID;
	pthread_attr_t attr;
	int ret;
    
	//获得对应IP以及端口号
	p=(struct TCPConThrParam*)param;
	HostIP = p->HostIP;
	BeginPort = p->BeginPort;
	EndPort = p->EndPort;
	
	//从BeginPort到EndPort的连接端口循环
    TCPConThrdNum = 0;
	for (TempPort=BeginPort;TempPort<=EndPort;TempPort++) 
	{
		//创建子线程
        //设置线程参数
        TCPConHostThrParam *pConHostParam = new TCPConHostThrParam;
        pConHostParam->HostIP = HostIP;
		pConHostParam->HostPort = TempPort;
		
		//设置线程为分离状态
		pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
        
		//创建连接子线程
		ret=pthread_create(&subThreadID,&attr,ThreadTCPconnectHost,pConHostParam);
		if (ret==-1) 
			cout<<"Can't create the TCP connect Host thread !"<<endl;
		pthread_attr_destroy(&attr);
		
		//计算线程数
		pthread_mutex_lock(&TCPConScanlocker);
        TCPConThrdNum++;
		pthread_mutex_unlock(&TCPConScanlocker);

		while (TCPConThrdNum>100)
			sleep(3);
	}

	//退出
	while (TCPConThrdNum != 0)
		sleep(1);
    cout<<"TCP Connect Scan thread exit !"<<endl;
	pthread_exit(NULL);
}
