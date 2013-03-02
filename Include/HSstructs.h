#pragma once
#include "winsock2.h"
#include "conio.h"
#include "stdlib.h"
#include <iostream>






// Ethernet header
typedef struct ethernet_header{
	UCHAR dest[6];								// Destination Address
	UCHAR source[6];							// Source Address  
	USHORT type;								// Protocol 
} ETHER_HDR , *PETHER_HDR , FAR * LPETHER_HDR , ETHERHeader; 


// Ip header (v4) 
typedef struct ip_hdr{ 
	unsigned char ip_header_len:4; 				// 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also) 
	unsigned char ip_version :4; 				// 4-bit IPv4 version 
	unsigned char ip_tos; 						// IP type of service 
	unsigned short ip_total_length; 			// Total length 
	unsigned short ip_id; 						// Unique identifier 
	unsigned char ip_frag_offset :5; 			// Fragment offset field 

	unsigned char ip_more_fragment :1; 
	unsigned char ip_dont_fragment :1; 
    unsigned char ip_reserved_zero :1; 
    unsigned char ip_frag_offset1;				// Fragment offset 
  
    unsigned char ip_ttl;						// Time to live 
	unsigned char ip_protocol;					// Protocol(TCP,UDP etc)
	unsigned short ip_checksum;					// IP checksum 
	unsigned int ip_srcaddr;					// Source address 
	unsigned int ip_destaddr;					// Source address 
} IPV4_HDR; 


// TCP header
typedef struct tcp_header{ 
	unsigned short source_port;					// Source port 
	unsigned short dest_port;					// Destination port 
	unsigned int sequence;						// Sequence number - 32 bits 
    unsigned int acknowledge;					// Acknowledgement number - 32 bits 

    unsigned char ns :1;						// Nonce Sum Flag Added in RFC 3540. 
	unsigned char reserved_part1:3;				// According to rfc 
	unsigned char data_offset:4;				// The number of 32-bit words in the TCP header
								
    unsigned char fin :1;						// Finish Flag 
	unsigned char syn :1;						// Synchronise Flag 
	unsigned char rst :1;						// Reset Flag 
	unsigned char psh :1;						// Push Flag 
	unsigned char ack :1;						// Acknowledgement Flag 
	unsigned char urg :1;						// Urgent Flag 
	 
	unsigned char ecn :1;						// ECN-Echo Flag 	   
	unsigned char cwr :1;						// Congestion Window Reduced Flag 

	unsigned short window;						// Window 
	unsigned short checksum;					// Checksum 
	unsigned short urgent_pointer;				// Urgent pointer 
} TCP_HDR; 