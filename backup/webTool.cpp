#include "StdAfx.h"
#include "webTool.h"
#include <sys\timeb.h>
#include <sys\types.h>
#include <sys\timeb.h>
#include <time.h>
#include "linked_list.h"
#include "linked_list_cont.h"


using namespace std;


// Инициализация параметров
webTool::webTool(void){
	char input[] = "C:\\input1.txt";
	strList = new str_list(input);
	strList->getByFile();

	numPackets = 0;							// Кол-во принимаемых пакетов, 0 - не ограниченное
	maxSizePacket = 1048576;				// Максимальный размер принимаемого пакета
	inOneFile = 0;							// Выводить пакеты в один файл или в отдельные
	
	if (inOneFile){
		// Имя выходного файла
		outFilename = "C:/output.txt";
	}
	else{
		// Имя выходного каталога
		outPath = "C:/output/";
	}

	findStringIn = 1;						// 0 - Искать только в HTTP-заголовке
											// 1 - Искать только в HTTP-data
											// 2 - Искать во всем HTTP-пакете
	str = L"";					
	tcp = 0, others = 0, good = 0, total = 0;
	timeout = 1000;
	filter_exp ="port 80 or port 8080";
	
	dev = pcap_lookupdev(errbuf);
	if (!dev){
		fprintf(stderr, "%s", errbuf);
		exit(1);
	}
}



// Запуск работы
void webTool::start(void){
	isExit = 0;								// Установка флага выхода
	setCurrentDevice();						// Установка сетевого устройства
	setFilter();							// Установка фильтра
	runSniffing();							// Запуск сниффинга
	int s = 4;
}



// Выбор сетевого устройства
void webTool::setCurrentDevice(void){
	// Получение списка устройств
    if (pcap_findalldevs(&alldevs, errbuf) == -1){
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit (1);
    }
   
    // Печать списка
    int deviceCnt=0;		
	pcap_if_t *d;
	fprintf(stdout,"LIST OF DEVICE\n");
	fprintf(stdout,"****************************************\n\n");
	for(d = alldevs; d; d=d->next){
        fprintf(stdout,"%d. %s", ++deviceCnt, d->name);
        if (d->description)
			fprintf(stdout," (%s)\n", d->description);
		else printf(" (No description available)\n");
	}
	fprintf(stdout,"\n****************************************\n\n");
	
	// Выбор устройства
	int devId = 1;
	do{
		fprintf(stdout, "Choice device (0<x<%d): ", deviceCnt+1);
		fscanf(stdin, "%d", &devId);
	}while ((devId>deviceCnt) || (devId<=0));
	
	d = alldevs;
	for (int i=1; d && i!=devId; ++i){
		d = d->next;
	}

	dev = d->name;
	fprintf(stdout, "\nCurrent device: %s\n\n", dev);
	initDevice();
}



// Инициализация выбранного устройства
void webTool::initDevice(void){
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, maxSizePacket, 1, timeout, errbuf);
	if (!handle){
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit (1);
	}
}



// Установка фильтра
void webTool::setFilter(void){
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit (2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit (2);
	}
}



// Инициализация выходного файла
void webTool::setOutput(void){ 
	fstream = fopen(outFilename, "a, ccs=UNICODE");
	if(!fstream){
		fprintf(stdout, "\nUnable to create file.");
		exit (3);
	} 
} 



// Обработка полученного TCP-пакета
int webTool::getTcpPacket(int onlyPrintPacket){
	int size = header->caplen;
	TCP_packet tcp_curr(packet,fstream,str,size,strList);

	if (onlyPrintPacket){
		setOutput();
		if (fstream != NULL) {
			tcp_curr.printTcpPacket(fstream);
			fclose(fstream);
		}
		return 0;	
	}

	if ((findStringIn == 0) && (tcp_curr.findInHTTPheader())){			// Поиск только в HTTP-Header
		setOutput();
		if (fstream != NULL) {
			tcp_curr.printTcpPacket(fstream);
			fclose(fstream);
		}
		return 1;
	};

	if ((findStringIn == 1) && (tcp_curr.findInHTTPdata())){			// Поиск только в HTTP-data
		setOutput();
		if (fstream != NULL) {
			tcp_curr.printTcpPacket(fstream);
			fclose(fstream);
		}
		return 1;
	};
	
	if ((findStringIn == 2) && (tcp_curr.findInHTTP())){				// Поиск во всем HTTP
		setOutput();
		if (fstream != NULL) {
			tcp_curr.printTcpPacket(fstream);
			fclose(fstream);
		}
		return 1;
	}
	
	return 0;
}



// Обработка пакетов
int webTool::workWithPacket(){
	ETHER_HDR *ethhdr;
	int size = header->caplen;
	ethhdr = (ETHER_HDR *)packet; 
	++total; 
	

	//Ip packets
	if(ntohs(ethhdr->type) == 0x0800){
		iphdr = (IPV4_HDR *)(packet + sizeof(ETHER_HDR));
		// Определение протокола
		switch (iphdr->ip_protocol){						
		case IPPROTO_TCP:												
			tcp++;	
			
			// Сохранять каждую сессию (с учетом фильтра) в отдельный файл
			if (!inOneFile){
				// Смотрим сохранены ли адреса источника/приемника, если да, то сохраняем пакет в нужный файл
				if (sessionList->findSaved(iphdr->ip_srcaddr,iphdr->ip_destaddr)){	
					outFilename = sessionList->findSaved(iphdr->ip_srcaddr,iphdr->ip_destaddr);
					getTcpPacket(1);
					break;
				}
							
				// Адреса источника/приемника не были найдены, поэтому ищем вхождение, 
				// если есть, то сохраняем инфу о источнике/приемнике
				if (getTcpPacket(0)){
					good++;
					sessionList->add(iphdr->ip_srcaddr,iphdr->ip_destaddr,outFilename);
					break;
				}
				break;
			}
			// Все пакеты в один файл
			if (getTcpPacket(0))
				good++;
			break;

		default:							// Другие протоколы
			others++; 
			break; 
		} 
	}
	fprintf(stdout,"Statistics package: TCP:%d  Others:%d  Good:%d  Total:%d\r" , tcp , others , good , total);
	return 0;
}



// Установка полного имени файла
void webTool::setOutputName(void){
	char date[100];
	char filename[100];
	char fullName[100];
	struct tm tbreak;

	time_t timer;
    struct tm *tblock;
    struct _timeb timebuffer;
    _ftime( &timebuffer );
    tblock = localtime(&timebuffer.time);
    strftime (date, 80, "%Y-%m-%d_%H-%M-%S.", tblock);
    _itoa(timebuffer.millitm, filename, 10);	
	strcat(date,filename);
	strcat(date,".txt");

	fullName[0]='\0';
	strcat(fullName,outPath);
	strcat(fullName,date);
	outFilename = new char[strlen(fullName)];
	outFilename[0] = '\0';
	strcpy(outFilename,fullName);
}



// Запуск сниффинга
int webTool::runSniffing(){
	u_int res;	
	fprintf(stdout,"Sniffing is runnig...\n(For stop sniffing press ctrl+c)\n\n");
	
	sessionList = new linked_list();

	while((!isExit) && ((res = pcap_next_ex(handle, &header, &packet)) >= 0)){        
		if(res == 0){											// Окончание таймаута
			continue;								
		} 
		if (!inOneFile){ 
			setOutputName();
		} 
		workWithPacket(); 
	}   
	if(res == -1){
		return -1; 
	}
	return 0;
}



// Остановка работы
void webTool::stop(void){
	isExit = 1;
}



// Освобождение ресурсов
webTool::~webTool(void){
	if (alldevs != NULL){
		pcap_freealldevs(alldevs);
	}
	if (strList != NULL){
		delete strList;
	}
	if (sessionList){
		delete(sessionList);
	}
	if (handle != NULL){
		pcap_close(handle);
	}
	if (fstream != NULL){
		fclose(fstream);
	}
}
