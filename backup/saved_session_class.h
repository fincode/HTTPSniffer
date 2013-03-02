#pragma once

struct SAVED_SESSION{
	unsigned int ip_srcaddr;					// Source address 
	unsigned int ip_destaddr;					// Destination Address
	char *session_filename;						// Session filename
	SAVED_SESSION *next;						// Link to next
};


class saved_session_class{
public:
	saved_session_class(void){};	
	
	virtual void add(unsigned int ip_srcaddr, unsigned int ip_destaddr, char *session_filename) = 0;
	virtual char* findSaved(unsigned int _ip_srcaddr, unsigned int _ip_destaddr) = 0;
	virtual void delAllList(void) = 0;
	virtual void deleteByIp(unsigned int ip_srcaddr, unsigned int ip_destaddr) = 0;
	virtual void deleteByFilename(char *session_filename) = 0;
	
	virtual ~saved_session_class(void){};
protected:
	int countElem;								// количество элементов в списке
};

