#pragma once
#include "HSSavedSessionClass.h"
#include <iterator>
#include <list>


class HSLinkedListCont : public HSSavedSessionClass{
public:
	HSLinkedListCont();	// Создание списка
	
	virtual void add(unsigned int _ip_srcaddr, unsigned int _ip_destaddr, char *_session_filename); // Добавление записи
	virtual char* findSaved(unsigned int _ip_srcaddr, unsigned int _ip_destaddr); // Поиск записи по IP
	
	virtual void deleteByIp(unsigned int ip_srcaddr, unsigned int ip_destaddr); // Удаление записи по IP
	virtual void deleteByFilename(char *filename);	// Удаление записи по имени файла
    virtual void delAllList(void); // Удаление всех записей
	
	virtual ~HSLinkedListCont();
private:
	 std::list<SAVED_SESSION> plist;
}; 

