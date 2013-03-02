#include "stdafx.h"
#include "HSStrList.h"
#include <boost/regex.hpp>
#include <boost/algorithm/string.hpp>


HSStrList::HSStrList(void){}

HSStrList::HSStrList(const HSStrList& ts)
{
	this->_countElem = ts._countElem;
	this->_curStr = ts._curStr;
	this->_filename = ts._filename;
	this->_slist = ts._slist;
}


// Создание списка
HSStrList::HSStrList(std::string str,HANDLE hLog)
{
	_countElem = 0;
	_hLog = hLog;
	_curStr = 0;
	_filename =  str;
}



// Добавление записи
void HSStrList::addStr(std::wstring str)
{	
	_slist.push_back(str);
	++_countElem;
}



bool isDelimiter(const char c) {return (c=='\n' || c==' ');}

// Парсинг строки
void HSStrList::parse(WCHAR *buf){
	std::wstring message = buf;
	std::list<std::wstring> tokens;
	boost::split(_slist, message, isDelimiter, boost::token_compress_on);
	std::list<std::wstring>::const_iterator it, it_begin = _slist.begin(), it_end = _slist.end();
	for (it = it_begin; it != it_end; ++it){ 
		++_countElem;
	}
}


void HSStrList::writeError(LPCTSTR text){
	if(_hLog != NULL){
		LPCTSTR ppParams[5] = {text};
		::ReportEvent(_hLog, EVENTLOG_INFORMATION_TYPE, 0, 512, NULL, 5, 0, ppParams, NULL);
	}
	fprintf(stdout,"%S", text);
}

// Загрузка из файла
int HSStrList::getByFile(void)
{
	DWORD cbRead;

	HANDLE hFile = CreateFileA(_filename.data(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE){
		writeError(_T("Can't CreateFile in getByFile HSStrList.cpp\n"));
		CloseHandle(_hLog);
		return FALSE;
	}

	DWORD bufSize = 0;
    bufSize = GetFileSize(hFile, NULL);
	if (bufSize == INVALID_FILE_SIZE){
		CloseHandle(hFile);
		writeError(_T("Can't GetFileSize in getByFile HSStrList.cpp\n"));
		CloseHandle(_hLog);
		return FALSE;
	}

	char *buf = NULL;
	buf = new char[bufSize/sizeof(char)+1];
	buf[bufSize/sizeof(char)] = 0;	

	int iResult = ReadFile(hFile, buf, bufSize, &cbRead, NULL);
	if((!iResult) || (cbRead != bufSize)){
		if (buf != NULL){ delete[] buf; }
		CloseHandle(hFile);
		writeError(_T("Can't ReadFile in getByFile HSStrList.cpp\n"));
		CloseHandle(_hLog);
		return FALSE;
	}

	ULONG  buf_size = strlen(buf)+1;  
	WCHAR *wData = NULL;
	wData = new WCHAR[buf_size];
	MultiByteToWideChar(CP_ACP, 0, buf, buf_size, wData, buf_size);
	
	parse(wData);

	if (wData != NULL){ delete[] wData; }
	if (buf != NULL){ delete[] buf; }
	CloseHandle(hFile);
//	CloseHandle(_hLog);
	return TRUE;
}





// Проверка регулярного выражения
BOOL HSStrList::regComp(std::wstring regExp, WCHAR* data)
{
	std::wstring str=data;
	boost::wregex exp(regExp);
	boost::wsmatch r;

	if(boost::regex_match(str,r,exp)){
		return TRUE;
	}
	return FALSE;
}



// Получение строки
WCHAR* HSStrList::getStr(void)
{
	if (_curStr == _countElem){ 
		_curStr = 0;
		return NULL;
	}
	std::list<std::wstring>::iterator i = _slist.begin();
	std::advance(i, _curStr);
	_curStr++;
	WCHAR* wStr = const_cast<wchar_t*>(i->c_str() );
	return wStr;
}



// Удаление списка
HSStrList::~HSStrList(void)
{
	_slist.clear();
	_countElem = 0;
}

