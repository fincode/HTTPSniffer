#pragma once
#include <Windows.h>
#include <list>


class HSStrList{
public:
	HSStrList(void);
	HSStrList(const HSStrList& ts);
	HSStrList(std::string str, HANDLE hLog);			// Создание списка
	
	void addStr(std::wstring str);						// Добавление записи 
	BOOL  getByFile(void);								// Загрузка из файла
	WCHAR* getStr(void);
	BOOL regComp(std::wstring regExp, WCHAR* data);
	void parse(WCHAR *buf);

	void writeError(LPCTSTR text);
	virtual ~HSStrList(void);
private:
	std::list<std::wstring> _slist;						
	int _countElem;
	int _curStr;
	HANDLE _hLog;
	std::string _filename;
};