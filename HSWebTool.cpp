#include "StdAfx.h"

#include "HSWebTool.h"
#include <sys\timeb.h>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/foreach.hpp>
#include <time.h>
#include <Packet32.h>
#include "HSLinkedList.h"
#include "HSLinkedListCont.h"
#include <boost/asio/detail/pop_options.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/detail/socket_types.hpp>
#include <boost/asio/detail/socket_ops.hpp>

using namespace std;


// Инициализация параметров
HSWebTool::HSWebTool(void)
{			
	_hLog = NULL;
	tcp = 0, others = 0, good = 0, total = 0;
}

// Инициализация Logevent
BOOL HSWebTool::initLogEvent(void){
	_hLog = RegisterEventSource(NULL, L"HTTP Sniffer");
	if (_hLog == NULL) return FALSE;
	return TRUE;
}



// Печать ошибок
void HSWebTool::writeError(LPCTSTR text){
	if(_hLog != NULL){
		LPCTSTR ppParams[5] = {text};
		::ReportEvent(_hLog, EVENTLOG_INFORMATION_TYPE, 0, 512, NULL, 5, 0, ppParams, NULL);
	}
	fprintf(stdout,"%S", text);
}



// Парсинг конфига
void HSWebTool::ParseConfig(const boost::property_tree::ptree& config)
{
	try{
		const boost::property_tree::ptree& main = config.get_child("main");
		_numPackets = main.get("numPackets",100);					
		_maxSizePacket = main.get("maxSizePacket",512);	
		_isSaveSession = main.get("saveSession", 0);
		_findDataIn = main.get("findDataIn", 2);
		_defualtDevice = main.get("defualtDevice", 1);
			
		_inFilename = main.get<string>("inFilename","input.txt");
		_outFilename = main.get<string>("outFilename","output.txt");
		_outPathForSession = main.get<string>("outPathForSession","output/");
		
		_timeout = main.get("timeout",1000);
		_filter_exp = main.get<string>("filter_exp", "port 80 or port 8080");
	}
	catch (const boost::property_tree::ptree_bad_data& error){
		writeError(_T("Bad data. Can't read config.ini\n"));
	}
	catch (const boost::property_tree::ptree_bad_path& error){
		writeError(_T("Bad path. Can't read config.ini\n"));
	}
}



// Парсинг файла
BOOL HSWebTool::ParseFile(const std::string& name, ParserType parser)
{
	boost::property_tree::ptree config;
	try{
		parser(name, config);
		ParseConfig(config);
		return TRUE;
	}
	catch (boost::property_tree::ini_parser_error& error){
		writeError(_T("\nCouldn't parse file\n"));
		return FALSE;
	}
}



// Парсинг INI-файла
void IniParser(const std::string& name, boost::property_tree::ptree& config)
{
	boost::property_tree::read_ini(name, config);
}



// Запуск работы
BOOL HSWebTool::start(int isService)
{
	_isService = isService;
	std:string configPath;
	if (_isService){
		configPath = "C:/Program Files (x86)/Dgleg softland/HTTP Sniffer 1.0/config.ini";
	}else configPath = "config.ini";
	
	if (!ParseFile(configPath, IniParser)){
		_numPackets = 0;					
		_maxSizePacket = 1048576;	
		_isSaveSession = 1;
		_findDataIn = 2;	
		_defualtDevice = 2;

		_outFilename = "output.txt";
		_outPathForSession = "output/";
		_inFilename = "input.txt";
		
		_timeout = 1000;
		_filter_exp = "port 80 or port 8080";
	}
	if (_isService){
		_outFilename = "C:/Program Files (x86)/Dgleg softland/HTTP Sniffer 1.0/output.txt";
		_outPathForSession = "C:/Program Files (x86)/Dgleg softland/HTTP Sniffer 1.0/output/";
		_inFilename = "C:/Program Files (x86)/Dgleg softland/HTTP Sniffer 1.0/input.txt";
	}

	_isExit = 0;						
	initLogEvent();

	_strList = new HSStrList(_inFilename,_hLog);
	// Парсинг input-файла
	if (!_strList->getByFile()){
		writeError(_T("Bad data. (!_strList->getByFile())  \n"));
		return FALSE;
	}			
	
	// Кол-во устройств
	int deviceCnt = getDeviceList();		
	if (!deviceCnt){
		writeError(_T("Device not found\n"));
		return FALSE;
	}

	// Установка сетевого устройства
	if (!setCurrentDevice(deviceCnt)){
		writeError(_T("Couldn't set device\n"));
		return FALSE;
	}			
	// Установка фильтра
	if (!setFilter()){				
		writeError(_T("Couldn't set filter\n"));
		return FALSE;
	};							
	_sessionList = new HSLinkedList();
	return TRUE;
}



// Получение списка устройств
BOOL HSWebTool::getDeviceList(void)
{
	if (pcap_findalldevs(&_alldevs, _errbuf) == -1){
		writeError(_T("Error in pcap_findalldevs\n"));
        return FALSE;
	}

	// Указатель на функцию GetAdaptersInfo
    typedef DWORD(CALLBACK* PTR_GETADAPTERSINFO)(PIP_ADAPTER_INFO,PULONG);
    HINSTANCE iphlpapi;
    iphlpapi=LoadLibrary(TEXT("iphlpapi.dll")); 
    if(!iphlpapi){
		writeError(_T("iphlpapi.dll not found\n"));
        return FALSE;
    }

    PTR_GETADAPTERSINFO GetAdaptersInfo;
    GetAdaptersInfo = (PTR_GETADAPTERSINFO)GetProcAddress (iphlpapi, "GetAdaptersInfo");
	if (GetAdaptersInfo == NULL){
		writeError(_T("Couldn't GetAdaptersInfo\n"));
		FreeLibrary(iphlpapi);
		return FALSE;
	}
	
	ULONG adapter_info_size = 0;
    PIP_ADAPTER_INFO ptr_adapter_info = NULL;
    PIP_ADAPTER_INFO ptr_adapter_info_first = NULL;

	if (GetAdaptersInfo( ptr_adapter_info, &adapter_info_size) == ERROR_SUCCESS){
		writeError(_T("Couldn't GetAdaptersInfo\n"));
		FreeLibrary(iphlpapi);
		return FALSE;
	}

    ptr_adapter_info = (PIP_ADAPTER_INFO) new(char[adapter_info_size] );

    if (GetAdaptersInfo( ptr_adapter_info, &adapter_info_size ) != ERROR_SUCCESS){
		writeError(_T("Error while GetAdaptersInfo\n"));
        if (ptr_adapter_info != NULL) delete( ptr_adapter_info );
        return FALSE;
    }

	int deviceCnt = printDeviceList(ptr_adapter_info);
	
	FreeLibrary(iphlpapi);
	if (ptr_adapter_info != NULL) delete( ptr_adapter_info );
	return deviceCnt;
}



// Печать списка
int HSWebTool::printDeviceList(PIP_ADAPTER_INFO ptr_adapter_info){
    int deviceCnt=0;		
	pcap_if_t *d;
	fprintf(stdout,"LIST OF DEVICE\n");
	fprintf(stdout,"****************************************\n\n");
	for(d = _alldevs; d; d=d->next){
        fprintf(stdout,"%d. %s", ++deviceCnt, d->name);
        if (d->description)
			fprintf(stdout," (%s)\n", d->description);
		else fprintf(stdout," (No description available)\n");		
		
		pcap_addr *curAddr = d->addresses;
		while (curAddr){
			if (curAddr->addr->sa_family == AF_INET6) {	
				struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)d->addresses->addr;	
				char ip6[INET6_ADDRSTRLEN]; // для сохранения строкового значения IP-адреса
				void* addr = &(ipv6->sin6_addr);
				inet_ntop(AF_INET6,addr,ip6,sizeof ip6);
				fprintf(stdout,"The address v6: %s\n", ip6);
			} else if (curAddr->addr->sa_family == AF_INET){
				struct sockaddr_in *ipv4 = (struct sockaddr_in *)curAddr->addr;	
				void* addr = &(ipv4->sin_addr);
				char ip[INET_ADDRSTRLEN]; 
				inet_ntop(AF_INET,addr,ip,sizeof ip);
				fprintf(stdout,"The address v4: %s\n", ip);
			};
			
			if (curAddr->broadaddr->sa_family == AF_INET6) {	
				struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)curAddr->broadaddr;	
				void* addr = &(ipv6->sin6_addr);
				char ip6[INET6_ADDRSTRLEN]; // для сохранения строкового значения IP-адреса
				inet_ntop(AF_INET6,addr,ip6,sizeof ip6);
				fprintf(stdout,"The broadaddr v6: %s\n", ip6);
			} else if (curAddr->broadaddr->sa_family == AF_INET){
				struct sockaddr_in *ipv4 = (struct sockaddr_in *)curAddr->broadaddr;	
				void* addr4 = &(ipv4->sin_addr);
				char ip4[INET_ADDRSTRLEN]; 
				inet_ntop(AF_INET,addr4,ip4,sizeof ip4);
				fprintf(stdout,"The broadaddr v4: %s\n", ip4);
			};


			if (curAddr->dstaddr != NULL){
				if (curAddr->dstaddr->sa_family == AF_INET6) {	
					struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)curAddr->dstaddr;	
					void* addr = &(ipv6->sin6_addr);
					char ip6[INET6_ADDRSTRLEN]; // для сохранения строкового значения IP-адреса
					inet_ntop(AF_INET6,addr,ip6,sizeof ip6);
					fprintf(stdout,"The dstaddr v6: %s\n", ip6);
				} else if (curAddr->dstaddr->sa_family == AF_INET){
					struct sockaddr_in *ipv4 = (struct sockaddr_in *)curAddr->dstaddr;	
					void* addr4 = &(ipv4->sin_addr);
					char ip4[INET_ADDRSTRLEN]; 
					inet_ntop(AF_INET,addr4,ip4,sizeof ip4);
					fprintf(stdout,"The dstaddr v4: %s\n", ip4);
				};
			}
			if (curAddr->netmask->sa_family == AF_INET6) {	
				struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)curAddr->netmask;	
				void* addr = &(ipv6->sin6_addr);
				char ip6[INET6_ADDRSTRLEN]; // для сохранения строкового значения IP-адреса
				inet_ntop(AF_INET6,addr,ip6,sizeof ip6);
				fprintf(stdout,"The netmask v6: %s\n", ip6);
			} else if (curAddr->netmask->sa_family == AF_INET){
				struct sockaddr_in *ipv4 = (struct sockaddr_in *)curAddr->netmask;	
				void* addr4 = &(ipv4->sin_addr);
				char ip4[INET_ADDRSTRLEN]; 
				inet_ntop(AF_INET,addr4,ip4,sizeof ip4);
				fprintf(stdout,"The netmask v4: %s\n", ip4);
			};
			curAddr = curAddr->next;
		}
		void *headAdapter = ptr_adapter_info;
		while( ptr_adapter_info ){
			if (strstr(d->name, ptr_adapter_info->AdapterName)){
				unsigned char *a1 = new unsigned char[(int)ptr_adapter_info->AddressLength];
				for( char i=0; i < (int)ptr_adapter_info->AddressLength; i++){
					a1[i] = (unsigned char)ptr_adapter_info->Address[i];
				}	
				fprintf(stdout, "The MAC: %02x-%02x-%02x-%02x-%02x-%02x\n",
					a1[0],
					a1[1],
					a1[2],
					a1[3],
					a1[4],
					a1[5]);
				if (a1 != NULL) 
					delete[] a1;
			}
			ptr_adapter_info = ptr_adapter_info->Next;
		}
    	fprintf(stdout,"\n");
		ptr_adapter_info = (PIP_ADAPTER_INFO)headAdapter;
	}
	fprintf(stdout,"\n****************************************\n\n");
	return deviceCnt;
}



// Выбор сетевого устройства
BOOL HSWebTool::setCurrentDevice(int deviceCnt)
{
	do{
		fprintf(stdout, "Choice device (0<x<%d): ", deviceCnt+1);
		if (fscanf(stdin, "%d", &_defualtDevice) != 1){
			fflush(stdin);
			continue;
		}
	}while ((_defualtDevice>deviceCnt) || (_defualtDevice<=0));
	
	pcap_if_t *d = _alldevs;
	for (int i=1; d && i!=_defualtDevice; ++i){
		d = d->next;
	}

	_dev = d->name;
	fprintf(stdout, "\nCurrent device: %s\n\n", _dev);
	if (!initDevice()){
		writeError(_T("Couldn't init Device\n"));
		return FALSE;
	};
	return TRUE;
}



// Инициализация выбранного устройства
BOOL HSWebTool::initDevice(void)
{
	if (pcap_lookupnet(_dev, &_net, &_mask, _errbuf) == -1){
		writeError(_T("Couldn't get netmask for device \n"));
		_net = 0;
		_mask = 0;
		return FALSE;
	}

	_handle = pcap_open_live(_dev, _maxSizePacket, 1, _timeout, _errbuf);
	if (!_handle){
		writeError(_T("Couldn't open device \n"));
		return FALSE;
	}
	return TRUE;
}



// Установка фильтра
int HSWebTool::setFilter(void)
{
	char *tmp = NULL;
	tmp = new char[_filter_exp.length()+1];
	tmp[_filter_exp.length()] = '\0';
	_filter_exp.copy(tmp,_filter_exp.length());
	if (pcap_compile(_handle, &_fp, tmp, 0, _net) == -1){
		writeError(_T("Couldn't parse filter\n"));
		if (tmp != NULL) delete[] tmp;
		return 0;
	}
	if (pcap_setfilter(_handle, &_fp) == -1) {
		writeError(_T("Couldn't install filter\n"));
		if (tmp != NULL) delete[] tmp;
		return 0;
	}
	if (tmp != NULL) 
		delete[] tmp;
	return 1;
}



// Инициализация выходного файла
BOOL HSWebTool::setOutput(void)
{ 
	_fstream = NULL;
	_fstream = fopen(_outFilename.data(), "a, ccs=UNICODE");
	if(_fstream == NULL){
		writeError(_T("Unable to create file\n"));
		return FALSE;
	} 
	return TRUE;
} 



// Обработка полученного TCP-пакета
BOOL HSWebTool::getTcpPacket(int onlyPrintPacket)
{
	int size = _header->caplen;
	HSTcpPacket tcp_curr(_packet,size,_strList);

	if (onlyPrintPacket){
		setOutput();
		if (_fstream != NULL) {
			tcp_curr.printTcpPacket(_fstream);
			fclose(_fstream);
			return FALSE;
		}
		return TRUE;	
	}

	if ((_findDataIn == 0) && (tcp_curr.findInHTTPheader())){			// Поиск только в HTTP-Header
		setOutput();
		if (_fstream != NULL) {
			tcp_curr.printTcpPacket(_fstream);
			fclose(_fstream);
		}
		return TRUE;
	};


	if ((_findDataIn == 1) && (tcp_curr.findInHTTPdata())){			// Поиск только в HTTP-data
		setOutput();
		if (_fstream != NULL) {
			tcp_curr.printTcpPacket(_fstream);
			fclose(_fstream);
		}
		return TRUE;
	};
	
	if ((_findDataIn == 2) && (tcp_curr.findInHTTP())){				// Поиск во всем HTTP
		setOutput();

		if (_fstream != NULL) {
			tcp_curr.printTcpPacket(_fstream);
			fclose(_fstream);
		}
		return TRUE;
	}
	return FALSE;
}



// Обработка пакетов
int HSWebTool::workWithPacket(void)
{
	ETHER_HDR *ethhdr; 
	int size = _header->caplen; 
	ethhdr = (ETHER_HDR *)_packet; 
	++total; 
	//Ip packets
	if(ntohs(ethhdr->type) == 0x0800){
		_iphdr = (IPV4_HDR *)(_packet + sizeof(ETHER_HDR));
		// Определение протокола
		switch (_iphdr->ip_protocol){	
		case IPPROTO_TCP:												
			tcp++;	
			// Сохранять каждую сессию (с учетом фильтра) в отдельный файл
			if (_isSaveSession){
				// Смотрим сохранены ли адреса источника/приемника, если да, то сохраняем пакет в нужный файл
				if (_sessionList->findSaved(_iphdr->ip_srcaddr,_iphdr->ip_destaddr)){	
					_outFilename.clear();
					_outFilename = _sessionList->findSaved(_iphdr->ip_srcaddr,_iphdr->ip_destaddr);
					getTcpPacket(1);
					break;
				}
							
				// Адреса источника/приемника не были найдены, поэтому ищем вхождение, 
				// если есть, то сохраняем инфу о источнике/приемнике
				if (getTcpPacket(0)){
					good++;					
					char *tmp = new char[_outFilename.length()+1];
					tmp[_outFilename.length()] = '\0';
					_outFilename.copy(tmp,_outFilename.length());
					_sessionList->add(_iphdr->ip_srcaddr,_iphdr->ip_destaddr,tmp);
					break;
				}
				break;
			}
			// Все пакеты сохраняем в один файл
			if (getTcpPacket(0)){
				good++;
			}	
			break;

		default:							// Другие протоколы 
			others++; 
			break; 
		} 
	}
	if(!_isService)
		fprintf(stdout,"Statistics package: TCP:%d  Others:%d  Good:%d  Total:%d\r" , tcp , others , good , total);
	return 0;
}



// Установка полного имени файла
void HSWebTool::setOutputName(void)
{
	string date;
	char time[100];
	string fullName;
	struct tm *tblock;
    struct _timeb timebuffer;
    _ftime( &timebuffer );
    tblock = localtime(&timebuffer.time);
	strftime (time, 80, "%Y-%m-%d_%H-%M-%S.", tblock);
	_outFilename.clear();
	_outFilename.append(_outPathForSession.data());	
	
	_outFilename.append(time);
	_itoa(timebuffer.millitm, time, 10);	
	_outFilename.append(time);
	_outFilename.append(".txt");
}



// Запуск сниффинга
BOOL HSWebTool::runSniffing()
{
	u_int res;	
	_packet = NULL;
	if (res = pcap_next_ex(_handle, &_header, &_packet) >= 0){
		if ((res == 0) || (_packet == NULL)){
			return FALSE;
		} 
		if (_isSaveSession){ 
			setOutputName();
		} 
		workWithPacket(); 
	}
	if(res == -1){
		return FALSE; 
	}
	return TRUE;
}


// Остановка работы
void HSWebTool::stop(void)
{	
	_isExit = 1; 
}


// Освобождение ресурсов
HSWebTool::~HSWebTool(void)
{
	if (_hLog != NULL) { DeregisterEventSource(_hLog); }
	if (_alldevs != NULL){ pcap_freealldevs(_alldevs); }
	if (_strList != NULL){ delete _strList; }
	if (_sessionList){ delete(_sessionList); }
	if (_handle != NULL){ pcap_close(_handle); }
	if (_fstream != NULL){ fclose(_fstream); }
}
