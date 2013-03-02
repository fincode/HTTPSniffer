#include "StdAfx.h"
#include "HSTcpPacket.h"
#include "HSWebTool.h"


// Инициализация данных
//HSTcpPacket::HSTcpPacket(const u_char *packet_, FILE *fstream, int packet_size_, HSStrList *strList_)
HSTcpPacket::HSTcpPacket(const u_char *packet_, int packet_size_, HSStrList *strList_)

{
//	_fstream = fstream;
	_packet = packet_;
	_listStr = *strList_;
	int packet_size = packet_size_;
	initPacketData(packet_size);
}



// Обработка пакета
void HSTcpPacket::initPacketData(int packet_size)
{
	unsigned short iphdrlen;
	int header_size = 0;
	_iphdr = (IPV4_HDR *)(_packet + sizeof(ETHER_HDR)); 
	iphdrlen = _iphdr->ip_header_len*4; 
  
	int tcphdrlen;	
	_tcpheader = (TCP_HDR*)(_packet + iphdrlen + sizeof(ETHER_HDR)); 
    tcphdrlen = _tcpheader->data_offset*4; 
    
	char *tmp = (char *)(_packet + sizeof(ETHER_HDR) + iphdrlen + tcphdrlen);
	ULONG  tmp_size = strlen(tmp)+1;  
	_data = new WCHAR[tmp_size + 1];
	_data[tmp_size] = L'\0';
	MultiByteToWideChar(CP_ACP, 0, tmp, tmp_size, _data, tmp_size);
}



// Поиск в HTTP-header
BOOL HSTcpPacket::findInHTTPheader(void)
{
	WCHAR *httpData;
	if (httpData = wcsstr(_data, L"\r\n\r\n")){
		int i;
		int dataLen =  wcslen(_data);
		int httpDataLen = wcslen(httpData);
		int httpHeadLen = dataLen - httpDataLen;
		WCHAR *httpHeader = NULL;
		httpHeader = new WCHAR[httpHeadLen + 1];

		for (i=0; &_data[i]!=&httpData[0]; i++){
			httpHeader[i] = _data[i];
		}

		httpHeader[i++] = '\0';	
		WCHAR* _str;

		
		while (_str = _listStr.getStr()){
			if ((wcsstr(httpHeader, _str)) || _listStr.regComp(_str, httpHeader)){
				if (httpHeader != NULL)	delete[] httpHeader;
				return TRUE;
			}
		}

		if(httpHeader != NULL) delete[] httpHeader;
	}
	return FALSE;
}



// Поиск в HTTP-_data
BOOL HSTcpPacket::findInHTTPdata(void)
{
	WCHAR *httpData;  
	if (httpData = wcsstr(_data, L"\r\n\r\n")){
		WCHAR* _str;
		while (_str = _listStr.getStr()){
			if ((wcsstr(httpData, _str)) || _listStr.regComp(_str,httpData)){   
				return FALSE;
			}
		}
	}
	return FALSE;
}



// Поиск во всем HTTP
int HSTcpPacket::findInHTTP(void)
{
	WCHAR* _str;	
	while (_str = _listStr.getStr()){
		if ((wcsstr(_data, _str)) || _listStr.regComp(_str, _data)){
			return TRUE;
		}
	}
	return FALSE;
}



// Печать Ethernet-заголовка
void HSTcpPacket::printEthernetHeader(FILE *_fstream)
{ 
	if (_fstream == NULL) return;

	ETHER_HDR *eth = (ETHER_HDR *)_packet; 
	fwprintf(_fstream,L"Ethernet Header\n"); 
	fwprintf(_fstream , L" |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->dest[0] , eth->dest[1] , eth->dest[2] , eth->dest[3] , eth->dest[4] , eth->dest[5] ); 
	fwprintf(_fstream , L" |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->source[0] , eth->source[1] , eth->source[2] , eth->source[3] , eth->source[4] , eth->source[5] ); 
	fwprintf(_fstream , L" |-Protocol            : 0x%.4x \n" , ntohs(eth->type) ); 
	fwprintf(_fstream,L"\n"); 
} 
	 


// Печать IP-заголовка
void HSTcpPacket::printIpHeader(FILE *_fstream)
{ 
	if (_fstream == NULL) return;

	int iphdrlen = 0; 
	_iphdr = (IPV4_HDR *)(_packet + sizeof(ETHER_HDR)); 
	iphdrlen = _iphdr->ip_header_len*4; 
	
	struct sockaddr_in source, dest;			// Адреса приемника и источника

	memset(&source, 0, sizeof(source)); 
	source.sin_addr.s_addr = _iphdr->ip_srcaddr; 
	
	memset(&dest, 0, sizeof(dest)); 
	dest.sin_addr.s_addr = _iphdr->ip_destaddr; 
	
	fwprintf(_fstream,L"IP Header\n");
	fwprintf(_fstream,L" |-IP Version : %d\n",(unsigned int)_iphdr->ip_version); 
	fwprintf(_fstream,L" |-IP Header Length : %d DWORDS or %d Bytes\n",(unsigned int)_iphdr->ip_header_len,((unsigned int)(_iphdr->ip_header_len))*4); 
	fwprintf(_fstream,L" |-Type Of Service : %d\n",(unsigned int)_iphdr->ip_tos); 
	fwprintf(_fstream,L" |-IP Total Length : %d Bytes(Size of _packet)\n",ntohs(_iphdr->ip_total_length)); 
	fwprintf(_fstream,L" |-Identification : %d\n",ntohs(_iphdr->ip_id));
	fwprintf(_fstream,L" |-Reserved ZERO Field : %d\n",(unsigned int)_iphdr->ip_reserved_zero); 
	fwprintf(_fstream,L" |-Dont Fragment Field : %d\n",(unsigned int)_iphdr->ip_dont_fragment); 
	fwprintf(_fstream,L" |-More Fragment Field : %d\n",(unsigned int)_iphdr->ip_more_fragment); 
	fwprintf(_fstream,L" |-TTL : %d\n",(unsigned int)_iphdr->ip_ttl); 
	fwprintf(_fstream,L" |-Protocol : %d\n",(unsigned int)_iphdr->ip_protocol); 
	fwprintf(_fstream,L" |-Checksum : %d\n",ntohs(_iphdr->ip_checksum)); 
	fwprintf(_fstream,L" |-Source IP : %S\n",inet_ntoa(source.sin_addr)); 
	fwprintf(_fstream,L" |-Destination IP : %S\n",inet_ntoa(dest.sin_addr)); 
	fwprintf(_fstream,L"\n");
}



// Печать TCP-заголовка
void HSTcpPacket::printTcpHeader(FILE *_fstream)
{
	if (_fstream == NULL) 
		return;

	fwprintf(_fstream,L"TCP Header\n");
	fwprintf(_fstream,L" |-Source Port : %u\n", ntohs(_tcpheader->source_port)); 
	fwprintf(_fstream,L" |-Destination Port : %u\n",ntohs(_tcpheader->dest_port)); 
	fwprintf(_fstream,L" |-Sequence Number : %u\n",ntohl(_tcpheader->sequence)); 
	fwprintf(_fstream,L" |-Acknowledge Number : %u\n",ntohl(_tcpheader->acknowledge));
	fwprintf(_fstream,L" |-Header Length : %d DWORDS or %d BYTES\n" , (unsigned int)_tcpheader->data_offset,(unsigned int)_tcpheader->data_offset*4); 
	fwprintf(_fstream,L" |-CWR Flag : %d\n",(unsigned int)_tcpheader->cwr); 
	fwprintf(_fstream,L" |-ECN Flag : %d\n",(unsigned int)_tcpheader->ecn); 
	fwprintf(_fstream,L" |-Urgent Flag : %d\n",(unsigned int)_tcpheader->urg); 
	fwprintf(_fstream,L" |-Acknowledgement Flag : %d\n",(unsigned int)_tcpheader->ack); 
	fwprintf(_fstream,L" |-Push Flag : %d\n",(unsigned int)_tcpheader->psh); 
	fwprintf(_fstream,L" |-Reset Flag : %d\n",(unsigned int)_tcpheader->rst); 
	fwprintf(_fstream,L" |-Synchronise Flag : %d\n",(unsigned int)_tcpheader->syn); 
	fwprintf(_fstream,L" |-Finish Flag : %d\n",(unsigned int)_tcpheader->fin); 
	fwprintf(_fstream,L" |-Window : %d\n",ntohs(_tcpheader->window)); 
	fwprintf(_fstream,L" |-Checksum : %d\n",ntohs(_tcpheader->checksum)); 
	fwprintf(_fstream,L" |-Urgent Pointer : %d\n",_tcpheader->urgent_pointer);
	fwprintf(_fstream,L"\n"); 
}



// Печать TCP-пакета
void HSTcpPacket::printTcpPacket(FILE *_fstream)
{
	if (_fstream == NULL) 
		return;
	fwprintf(_fstream, L"##### TCP _packet #####\n");
	fwprintf(_fstream,L"\n");
	
	printEthernetHeader(_fstream);
	printIpHeader(_fstream);
	printTcpHeader(_fstream); 
	
	fwprintf(_fstream,L"_data Payload\n"); 
	fputws(_data,_fstream);
	fwprintf(_fstream,L"\n###########################################################\n\n\n");
}



HSTcpPacket::~HSTcpPacket(void){
	if (_data != NULL) 
		delete[] _data;
}

