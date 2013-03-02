#include "StdAfx.h"
#include "HSLinkedListCont.h"


HSLinkedListCont::HSLinkedListCont() : HSSavedSessionClass(){
	_countElem = 0;
}



void HSLinkedListCont::add(unsigned int _ip_srcaddr, unsigned int _ip_destaddr, char *_session_filename){
	SAVED_SESSION tmp;
	tmp.ip_destaddr = _ip_destaddr;
	tmp.ip_srcaddr = _ip_srcaddr;
	tmp.session_filename = _session_filename;

	plist.push_back(tmp);
	++_countElem;
}



// Удаление записи по IP
void HSLinkedListCont::deleteByIp(unsigned int _ip_srcaddr, unsigned int _ip_destaddr){
	std::list<SAVED_SESSION>::const_iterator it, it_begin = plist.begin(), it_end = plist.end();
	for (it = it_begin; it != it_end; ++it){ 
		if ((it->ip_destaddr == _ip_destaddr) && (it->ip_srcaddr == _ip_srcaddr) ||
			(it->ip_destaddr == _ip_srcaddr) && (it->ip_srcaddr == _ip_destaddr)){
			plist.erase(it);
			--_countElem;
			return;
		}
	}
	return;
}



// Удаление записи по имени файла
void HSLinkedListCont::deleteByFilename(char *filename){
	std::list<SAVED_SESSION>::const_iterator it, it_begin = plist.begin(), it_end = plist.end();
	for (it = it_begin; it != it_end; ++it){ 
		if (it->session_filename == filename){
			plist.erase(it);
			--_countElem;
			return;
		}
	}
	return;
}


char* HSLinkedListCont::findSaved(unsigned int _ip_srcaddr, unsigned int _ip_destaddr){
	std::list<SAVED_SESSION>::const_iterator it, it_begin = plist.begin(), it_end = plist.end();
	for (it = it_begin; it != it_end; ++it){ 
		if ((it->ip_destaddr == _ip_destaddr) && (it->ip_srcaddr == _ip_srcaddr) ||
			(it->ip_destaddr == _ip_srcaddr) && (it->ip_srcaddr == _ip_destaddr))
			return (it->session_filename);
	}
	return NULL;
}




void HSLinkedListCont::delAllList(void){
	plist.clear();
	_countElem = 0;
}



HSLinkedListCont::~HSLinkedListCont(){
	delAllList();
}
