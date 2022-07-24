#include "TCPSYNScan.h"

void* ThreadTCPSYNHost(void* param)
{
	struct TCPSYNHostThrParam *p;
	string HostIP;
	unsigned HostPort,LocalPort,LocalHostIP;
	int SynSock;
	int len; 
	char sendbuf[8192]; 
	char recvbuf[8192];
	struct sockaddr_in SYNScanHostAddr;

    //获得IP地址与端口号
    p=(struct TCPSYNHostThrParam*)param;
    HostIP = p->HostIP;
	HostPort = p->HostPort;
	LocalPort = p->LocalPort;
	LocalHostIP = p->LocalHostIP;

 	//设置TCP SYN扫描主机地址
	memset(&SYNScanHostAddr,0,sizeof(SYNScanHostAddr));
	SYNScanHostAddr.sin_family = AF_INET;
	SYNScanHostAddr.sin_addr.s_addr = inet_addr(&HostIP[0]);
	SYNScanHostAddr.sin_port = htons(HostPort);  

	//创建socket连接
	SynSock=socket(PF_INET, SOCK_RAW, IPPROTO_TCP); 
	if ( SynSock<0 ) 
	{
		pthread_mutex_lock(&TCPSynPrintlocker);
		cout<<"Can't creat raw socket !"<<endl;
		pthread_mutex_unlock(&TCPSynPrintlocker);
	}
	   
	//填充TCP SYN数据包
    struct pseudohdr *ptcph=(struct pseudohdr*)sendbuf; 
    struct tcphdr *tcph=(struct tcphdr*)(sendbuf+sizeof(struct pseudohdr)); 

	ptcph->saddr = LocalHostIP; 
    ptcph->daddr = inet_addr(&HostIP[0]); 
    ptcph->useless = 0; 
    ptcph->protocol = IPPROTO_TCP; 
    ptcph->length = htons(sizeof(struct tcphdr));


    tcph->th_sport=htons(LocalPort);  
    tcph->th_dport=htons(HostPort); 
    tcph->th_seq=htonl(123456); 
    tcph->th_ack=0; 
    tcph->th_x2=0; 
    tcph->th_off=5; 
    tcph->th_flags=TH_SYN; 
    tcph->th_win=htons(65535); 
    tcph->th_sum=0; 
    tcph->th_urp=0; 
	tcph->th_sum=in_checksum((unsigned short*)ptcph, 20+12); 
    
	//发送TCP SYN数据包
	len=sendto(SynSock, tcph, 20, 0, (struct sockaddr *)&SYNScanHostAddr, sizeof(SYNScanHostAddr)); 
	if( len < 0) 
	{
		pthread_mutex_lock(&TCPSynPrintlocker);
		cout<<"Send TCP SYN Packet error !"<<endl;
		pthread_mutex_unlock(&TCPSynPrintlocker);		
	}

	//接受TCP回复
	len=read(SynSock, recvbuf, 8192); 
	if(len <= 0)
	{
		pthread_mutex_lock(&TCPSynPrintlocker);
		cout<<"Read TCP SYN Packet error !"<<endl;
		pthread_mutex_unlock(&TCPSynPrintlocker);
	}
	else
	{
		struct ip *iph=(struct ip *)recvbuf; 
        int i=iph->ip_hl*4; 
        struct tcphdr *tcph=(struct tcphdr *)&recvbuf[i]; 

		string SrcIP = inet_ntoa(iph->ip_src);       //TCP响应报文中的源IP
		string DstIP = inet_ntoa(iph->ip_dst);       //TCP响应报文中的目的IP地址
		struct in_addr in_LocalhostIP;
		in_LocalhostIP.s_addr = LocalHostIP;
		string LocalIP = inet_ntoa(in_LocalhostIP);  //本地IP地址

		unsigned SrcPort = ntohs(tcph->th_sport);    //TCP响应报文中的源端口号
		unsigned DstPort = ntohs(tcph->th_dport);    //TCP响应报文中的目的端口

		if(HostIP == SrcIP && LocalIP == DstIP && SrcPort == HostPort && DstPort == LocalPort)
		{
			if (tcph->th_flags == 0x14) 
			{  
				pthread_mutex_lock(&TCPSynPrintlocker);
				cout<<"Host: "<<SrcIP<<" Port: "<<ntohs(tcph->th_sport)<<" closed !"<<endl;
				pthread_mutex_unlock(&TCPSynPrintlocker);
			}
			if (tcph->th_flags == 0x12) 
			{
				pthread_mutex_lock(&TCPSynPrintlocker);
				cout<<"Host: "<<SrcIP<<" Port: "<<ntohs(tcph->th_sport)<<" open !"<<endl;
				pthread_mutex_unlock(&TCPSynPrintlocker);
			}		
		}

	}

    //退出
	delete p;
	close(SynSock);
	pthread_mutex_lock(&TCPSynScanlocker);
    TCPSynThrdNum--;
	pthread_mutex_unlock(&TCPSynScanlocker);
}

void* ThreadTCPSynScan(void* param)
{
    struct TCPSYNThrParam *p;

	string HostIP;
	unsigned BeginPort,EndPort,TempPort,LocalPort,LocalHostIP;

	pthread_t listenThreadID,subThreadID;
	pthread_attr_t attr,lattr;
	int ret;

	//获得IP地址与端口号
	p=(struct TCPSYNThrParam*)param;
	HostIP = p->HostIP;
	BeginPort = p->BeginPort;
	EndPort = p->EndPort;
	LocalHostIP = p->LocalHostIP;
	

	//循环扫描从BeginPort到EndPort
	TCPSynThrdNum = 0;
	LocalPort = 1024;

	for (TempPort=BeginPort;TempPort<=EndPort;TempPort++) 
	{
		//创建子线程
        //设置线程参数
        struct TCPSYNHostThrParam *pTCPSYNHostParam = new TCPSYNHostThrParam;
        pTCPSYNHostParam->HostIP = HostIP;
		pTCPSYNHostParam->HostPort = TempPort;
        pTCPSYNHostParam->LocalPort = TempPort + LocalPort;
		pTCPSYNHostParam->LocalHostIP = LocalHostIP;

		//设置线程为分离状态
		pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
                
		//创建TCP SYN线程
		ret=pthread_create(&subThreadID,&attr,ThreadTCPSYNHost,pTCPSYNHostParam);
		if (ret==-1) 
			cout<<"Can't create the TCP SYN Scan Host thread !"<<endl;

		//销毁线程
		pthread_attr_destroy(&attr);
		//计算线程数量
		pthread_mutex_lock(&TCPSynScanlocker);
        TCPSynThrdNum++;
		pthread_mutex_unlock(&TCPSynScanlocker);

		while (TCPSynThrdNum>100)
			sleep(3);
	}
	while (TCPSynThrdNum != 0)
		sleep(1);

    cout<<"TCP SYN scan thread exit !"<<endl;
	pthread_exit(NULL);
}

