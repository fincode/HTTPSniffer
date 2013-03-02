#pragma once
#include "HSstructs.h"
#include "HSStrList.h"	


class HSTcpPacket{
public:
	HSTcpPacket(const u_char *packet_, int packet_size_, HSStrList *strList_);
	void initPacketData(int packet_size);		// Обработка пакета 

	BOOL findInHTTPheader(void);				// Поиск только в HTTP-header
	BOOL findInHTTPdata(void);					// Поиск только в HTTP-data
	BOOL findInHTTP(void);						// Поиск во всем HTTP

	void printTcpPacket(FILE *_fstream);		// Вывод TCP-пакета
	void printEthernetHeader(FILE *_fstream);	// Вывод Enternet-заголовка	
	void printTcpHeader(FILE *_fstream);		// Вывод TCP-заголовка
	void printIpHeader (FILE *_fstream);		// Вывод IP-заголовка

	virtual ~HSTcpPacket(void);

private:
	TCP_HDR *_tcpheader;						// TCP-заголовок
	IPV4_HDR *_iphdr;							// IP-заголовок
	
	FILE *_fstream;								// Выходной файл
	const u_char *_packet;						// Текущий пакет
												// Ключевое слово для поиска соответствия
	WCHAR *_data;								// Данные пакета
	HSStrList _listStr;							// Список слов для поиска 

};

