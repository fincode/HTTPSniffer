#pragma once
#include "HSSavedSessionClass.h"

class HSLinkedList: public HSSavedSessionClass{
public:
	HSLinkedList(void);			// Создание списка
	
	virtual void add(unsigned int _ip_srcaddr, unsigned int _ip_destaddr, char *_session_filename); // Добавление записи в список
	virtual char* findSaved(unsigned int _ip_srcaddr, unsigned int _ip_destaddr);	// Поиск существующей записи
	void deleteRecord(SAVED_SESSION *pDelete);			// Удаление записи
	virtual void deleteByIp(unsigned int ip_srcaddr, unsigned int ip_destaddr); // Удаление записи по адресам
	virtual void deleteByFilename(char *filename);		// Удаление записи по имени файла
    virtual void delAllList(void);						// Удаление всех записей

	virtual ~HSLinkedList();

private:
	SAVED_SESSION *_pHead;						// указатель на первый элемент списка
    SAVED_SESSION *_pPrev;						// указатель на последний элемент списка
};

