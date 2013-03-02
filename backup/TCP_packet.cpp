#include "StdAfx.h"
#include "TCP_packet.h"
#include "webTool.h"


// Инициализация данных
TCP_packet::TCP_packet(const u_char *packet_, FILE *fstream_, WCHAR *str_, int packet_size_, str_list *strList_){
	fstream = fstream_;
	packet = packet_;
	str = str_;
	listStr = new str_list("");
	listStr = strList_;
	int packet_size = packet_size_;
	initPacketData(packet_size);
}



//WCHAR* cwsms_ansi_to_unicode(const char* ansi_str){
//	size_t len = strlen(ansi_str);
//	WCHAR *wstr = (WCHAR*) malloc (len);
//	if (!wstr)
//		return NULL;
//	MultiByteToWideChar(CP_ACP, 0, ansi_str, (int)len, wstr, (int)len);
//	return wstr;
//}



// Обработка пакета
void TCP_packet::initPacketData(int packet_size){
	unsigned short iphdrlen;
	int header_size = 0;
	iphdr = (IPV4_HDR *)(packet + sizeof(ETHER_HDR)); 
	iphdrlen = iphdr->ip_header_len*4; 
  
	int tcphdrlen;	
	tcpheader = (TCP_HDR*)(packet + iphdrlen + sizeof(ETHER_HDR)); 
    tcphdrlen = tcpheader->data_offset*4; 
    
	char *tmp = (char *)(packet + sizeof(ETHER_HDR) + iphdrlen + tcphdrlen);
	ULONG  tmp_size = strlen(tmp)+1;  
	data = new WCHAR[tmp_size];
	MultiByteToWideChar(CP_ACP, 0, tmp, tmp_size, data, tmp_size);
}





// Поиск в HTTP-header
int TCP_packet::findInHTTPheader(void){
	WCHAR *httpData;
	if (httpData = wcsstr(data, L"\r\n\r\n")){
		int i;
		int dataLen =  wcslen(data);
		int httpDataLen = wcslen(httpData);
		int httpHeadLen = dataLen - httpDataLen;
		WCHAR *httpHeader = new WCHAR[httpHeadLen];
		
		for (i=0; &data[i]!=&httpData[0]; i++){
			httpHeader[i] = data[i];
		} 
		
		httpHeader[i++] = '0';	
		while (str = listStr->getStr()){
			if (wcsstr(httpHeader, str)){
				if (httpHeader != NULL) delete[] httpHeader;
				return 1;
			}
		}
		if (httpHeader != NULL)	delete[] httpHeader;
	}
	return 0;
}



// Поиск в HTTP-data
int TCP_packet::findInHTTPdata(void){
	WCHAR *httpData;  
	if (httpData = wcsstr(data, L"\r\n\r\n")){
		while (str = listStr->getStr()){
			if (wcsstr(httpData, str)){   
				return 1;
			}
		}
	}
	return 0;
}



// Поиск во всем HTTP
int TCP_packet::findInHTTP(void){
	while (str = listStr->getStr()){
		if (wcsstr(data, str)){
			return 1;
		}
	}
	return 0;
}



// Печать Ethernet-заголовка
void TCP_packet::printEthernetHeader(){ 
	if (fstream == NULL) return;

	ETHER_HDR *eth = (ETHER_HDR *)packet; 
	fwprintf(fstream,L"Ethernet Header\n"); 
	fwprintf(fstream , L" |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->dest[0] , eth->dest[1] , eth->dest[2] , eth->dest[3] , eth->dest[4] , eth->dest[5] ); 
	fwprintf(fstream , L" |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->source[0] , eth->source[1] , eth->source[2] , eth->source[3] , eth->source[4] , eth->source[5] ); 
	fwprintf(fstream , L" |-Protocol            : 0x%.4x \n" , ntohs(eth->type) ); 
	fwprintf(fstream,L"\n"); 
} 
	 


// Печать IP-заголовка
void TCP_packet::printIpHeader(){ 
	if (fstream == NULL) return;

	int iphdrlen = 0; 
	iphdr = (IPV4_HDR *)(packet + sizeof(ETHER_HDR)); 
	iphdrlen = iphdr->ip_header_len*4; 
	struct sockaddr_in source, dest;			// Адреса приемника и источника

	memset(&source, 0, sizeof(source)); 
	source.sin_addr.s_addr = iphdr->ip_srcaddr; 
	
	memset(&dest, 0, sizeof(dest)); 
	dest.sin_addr.s_addr = iphdr->ip_destaddr; 
	
	fwprintf(fstream,L"IP Header\n");
	fwprintf(fstream,L" |-IP Version : %d\n",(unsigned int)iphdr->ip_version); 
	fwprintf(fstream,L" |-IP Header Length : %d DWORDS or %d Bytes\n",(unsigned int)iphdr->ip_header_len,((unsigned int)(iphdr->ip_header_len))*4); 
	fwprintf(fstream,L" |-Type Of Service : %d\n",(unsigned int)iphdr->ip_tos); 
	fwprintf(fstream,L" |-IP Total Length : %d Bytes(Size of Packet)\n",ntohs(iphdr->ip_total_length)); 
	fwprintf(fstream,L" |-Identification : %d\n",ntohs(iphdr->ip_id));
	fwprintf(fstream,L" |-Reserved ZERO Field : %d\n",(unsigned int)iphdr->ip_reserved_zero); 
	fwprintf(fstream,L" |-Dont Fragment Field : %d\n",(unsigned int)iphdr->ip_dont_fragment); 
	fwprintf(fstream,L" |-More Fragment Field : %d\n",(unsigned int)iphdr->ip_more_fragment); 
	fwprintf(fstream,L" |-TTL : %d\n",(unsigned int)iphdr->ip_ttl); 
	fwprintf(fstream,L" |-Protocol : %d\n",(unsigned int)iphdr->ip_protocol); 
	fwprintf(fstream,L" |-Checksum : %d\n",ntohs(iphdr->ip_checksum)); 
	fwprintf(fstream,L" |-Source IP : %S\n",inet_ntoa(source.sin_addr)); 
	fwprintf(fstream,L" |-Destination IP : %S\n",inet_ntoa(dest.sin_addr)); 
	fwprintf(fstream,L"\n"); 
}



// Печать TCP-заголовка
void TCP_packet::printTcpHeader(){
	if (fstream == NULL) return;

	fwprintf(fstream,L"TCP Header\n");
	fwprintf(fstream,L" |-Source Port : %u\n", ntohs(tcpheader->source_port)); 
	fwprintf(fstream,L" |-Destination Port : %u\n",ntohs(tcpheader->dest_port)); 
	fwprintf(fstream,L" |-Sequence Number : %u\n",ntohl(tcpheader->sequence)); 
	fwprintf(fstream,L" |-Acknowledge Number : %u\n",ntohl(tcpheader->acknowledge));
	fwprintf(fstream,L" |-Header Length : %d DWORDS or %d BYTES\n" , (unsigned int)tcpheader->data_offset,(unsigned int)tcpheader->data_offset*4); 
	fwprintf(fstream,L" |-CWR Flag : %d\n",(unsigned int)tcpheader->cwr); 
	fwprintf(fstream,L" |-ECN Flag : %d\n",(unsigned int)tcpheader->ecn); 
	fwprintf(fstream,L" |-Urgent Flag : %d\n",(unsigned int)tcpheader->urg); 
	fwprintf(fstream,L" |-Acknowledgement Flag : %d\n",(unsigned int)tcpheader->ack); 
	fwprintf(fstream,L" |-Push Flag : %d\n",(unsigned int)tcpheader->psh); 
	fwprintf(fstream,L" |-Reset Flag : %d\n",(unsigned int)tcpheader->rst); 
	fwprintf(fstream,L" |-Synchronise Flag : %d\n",(unsigned int)tcpheader->syn); 
	fwprintf(fstream,L" |-Finish Flag : %d\n",(unsigned int)tcpheader->fin); 
	fwprintf(fstream,L" |-Window : %d\n",ntohs(tcpheader->window)); 
	fwprintf(fstream,L" |-Checksum : %d\n",ntohs(tcpheader->checksum)); 
	fwprintf(fstream,L" |-Urgent Pointer : %d\n",tcpheader->urgent_pointer);
	fwprintf(fstream,L"\n"); 
}



// Печать TCP-пакета
void TCP_packet::printTcpPacket(FILE *fstream_){

	if (fstream_ == NULL) return;

	fstream = fstream_;
	fwprintf(fstream, L"##### TCP Packet #####\n");
	fwprintf(fstream,L"\n");
	
	printEthernetHeader();
	printIpHeader();
	printTcpHeader(); 
	
	fwprintf(fstream,L"Data Payload\n"); 
	fputws(data,fstream);

	fwprintf(fstream,L"\n###########################################################\n\n\n");
}



TCP_packet::~TCP_packet(void){
	if (data != NULL){
		delete[] data;
	}
}
