#include "Scaner.h"

int main(int argc,char* argv[])
{
    string HostIP;
	unsigned BeginPort,EndPort,LocalHostIP;
	int ret;

	struct TCPConThrParam TCPConParam;
	struct UDPThrParam UDPParam;
	struct TCPSYNThrParam TCPSynParam;
	struct TCPFINThrParam TCPFinParam;
	pthread_t ThreadID;

	char* pTcpCon = {"-c"};           // 进行 TCP connect 扫描
    char* pTcpSyn = {"-s"};           // 进行 TCP SYN 扫描
	char* pTcpFin = {"-f"};           // 进行 TCP FIN 扫描
	char* pUdp = {"-u"};              // 进行 TCP UDP 扫描
	char* pHelp = {"-h"};             // 帮助指令

	
	//参数是否符合规范
	if (argc != 2) 
	{
		cout<<"Parameter error !"<<endl;
		return -1;
	}

	//输出帮助指令
	if (!strcmp(pHelp,argv[1]))
	{
		cout<<"Scaner: usage: [-h]  --help information"<<endl;
		cout<<"               [-c]  --TCP connect scan"<<endl;
        cout<<"               [-s]  --TCP syn scan"<<endl;
	    cout<<"               [-f]  --TCP fin scan"<<endl;
		cout<<"               [-u]  --UDP scan"<<endl;
        return 1;
	}

    //输入IP地址
	cout<<"Please input IP address of a Host:";
	cin>>HostIP;

        
    if(inet_addr(&(HostIP[0])) == INADDR_NONE)
	{
            cout<<"IP address wrong!"<<endl;
            return -1;
	}
   
    //输入端口的范围
	cout<<"Please input the range of port..."<<endl;
	cout<<"Begin Port:";
	cin>>BeginPort;
	cout<<"End Port:";
	cin>>EndPort;
	
	if(IsPortOK(BeginPort,EndPort))
		cout<<"Scan Host "<<HostIP<<" port "<<BeginPort<<"~"<<EndPort<<" ..."<<endl;

	else
	{
		cout<<"The range of port is wrong !"<<endl;
        return -1;
	}
	
	//加载IP地址
	LocalHostIP = GetLocalHostIP();
	
	//PING连接不成功后的处理
	if (Ping(HostIP,LocalHostIP) == false) 
	{
		cout<<"Ping Host "<<HostIP<<" failed, stop scan it !"<<endl;
		return -1;
	}
 
	//TCP连接
	if (!strcmp(pTcpCon,argv[1]))
	{
		cout<<"Begin TCP connect scan..."<<endl;
		//create thread for TCP connect scan
        TCPConParam.HostIP = HostIP;
        TCPConParam.BeginPort = BeginPort;
        TCPConParam.EndPort = EndPort;
        ret = pthread_create(&ThreadID,NULL,ThreadTCPconnectScan,&TCPConParam);
	    if (ret==-1) 
		{
			cout<<"Can't create the TCP connect scan thread !"<<endl;
			return -1;
		}
		ret = pthread_join(ThreadID,NULL);
		if(ret != 0)
		{
			cout<<"call pthread_join function failed !"<<endl;
			return -1;
		}
		else
		{
			cout<<"TCP Connect Scan finished !"<<endl;
			return 0;
		}
	}
	//TCP SYN连接
	if (!strcmp(pTcpSyn,argv[1]))
	{
		cout<<"Begin TCP SYN scan..."<<endl;
		//create thread for TCP SYN scan
        TCPSynParam.HostIP = HostIP;
        TCPSynParam.BeginPort = BeginPort;
        TCPSynParam.EndPort = EndPort;
	    TCPSynParam.LocalHostIP = LocalHostIP;
        ret = pthread_create(&ThreadID,NULL,ThreadTCPSynScan,&TCPSynParam);
	    if (ret==-1) 
		{
			cout<<"Can't create the TCP SYN scan thread !"<<endl;
			return -1;
		}

		ret = pthread_join(ThreadID,NULL);
		if(ret != 0)
		{
			cout<<"call pthread_join function failed !"<<endl;
			return -1;
		}
		else
		{
			cout<<"TCP SYN Scan finished !"<<endl;
			return 0;
		}
	}
	//TCP FIN连接
	if (!strcmp(pTcpFin,argv[1]))
	{
		cout<<"Begin TCP FIN scan..."<<endl;
		//create thread for TCP FIN scan
        TCPFinParam.HostIP = HostIP;
        TCPFinParam.BeginPort = BeginPort;
        TCPFinParam.EndPort = EndPort;
	    TCPFinParam.LocalHostIP = LocalHostIP;
        ret = pthread_create(&ThreadID,NULL,ThreadTCPFinScan,&TCPFinParam);
	    if (ret==-1) 
		{
			cout<<"Can't create the TCP FIN scan thread !"<<endl;
			return -1;
		}

		ret = pthread_join(ThreadID,NULL);
		if(ret != 0)
		{
			cout<<"call pthread_join function failed !"<<endl;
			return -1;
		}
		else
		{
			cout<<"TCP FIN Scan finished !"<<endl;
			return 0;
		}
	}
	//UDP连接
    if (!strcmp(pUdp,argv[1]))
	{
		cout<<"Begin UDP scan..."<<endl;
		//创建好UDP连接
        UDPParam.HostIP = HostIP;
        UDPParam.BeginPort = BeginPort;
        UDPParam.EndPort = EndPort;
		UDPParam.LocalHostIP = LocalHostIP;
        ret = pthread_create(&ThreadID,NULL,ThreadUDPScan,&UDPParam);
		if (ret==-1) 
		{
			cout<<"Can't create the UDP scan thread !"<<endl;
			return -1;
		}

		ret = pthread_join(ThreadID,NULL);
		if(ret != 0)
		{
			cout<<"call pthread_join function failed !"<<endl;
			return -1;
		}
		else
		{
			cout<<"UDP Scan finished !"<<endl;
			return 0;
		}
	}
}

