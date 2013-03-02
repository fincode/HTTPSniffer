#pragma once

struct SAVED_SESSION{
	unsigned int ip_srcaddr;					// Source address 
	unsigned int ip_destaddr;					// Destination Address
	char *session_filename;						// Session filename
	SAVED_SESSION *next;						// Link to next
};


class HSSavedSessionClass{
public:
	HSSavedSessionClass(void){};	
	
	virtual void add(unsigned int ip_srcaddr, unsigned int ip_destaddr, char *session_filename) = 0;
	virtual char* findSaved(unsigned int _ip_srcaddr, unsigned int _ip_destaddr) = 0;
	virtual void delAllList(void) = 0;
	virtual void deleteByIp(unsigned int ip_srcaddr, unsigned int ip_destaddr) = 0;
	virtual void deleteByFilename(char *session_filename) = 0;
	
	virtual ~HSSavedSessionClass(void){};
protected:
	int _countElem;								// количество элементов в списке
};

