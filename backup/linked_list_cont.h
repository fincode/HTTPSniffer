#pragma once
#include "saved_session_class.h"
#include <iostream>
#include <algorithm>
#include <functional>
#include <iterator>
#include <list>
#include <cstdlib>


class linked_list_cont : public saved_session_class{
public:
	linked_list_cont();	// Создание списка
	
	virtual void add(unsigned int _ip_srcaddr, unsigned int _ip_destaddr, char *_session_filename); // Добавление записи
	virtual char* findSaved(unsigned int _ip_srcaddr, unsigned int _ip_destaddr); // Поиск записи по IP
	
	virtual void deleteByIp(unsigned int ip_srcaddr, unsigned int ip_destaddr); // Удаление записи по IP
	virtual void deleteByFilename(char *filename);	// Удаление записи по имени файла
    virtual void delAllList(void); // Удаление всех записей
	
	virtual ~linked_list_cont();
private:
	 std::list<SAVED_SESSION> plist;
}; 

