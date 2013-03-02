#include "stdafx.h"
#include "str_list_t.h"
#include <boost/regex.h>

// Создание списка
str_list::str_list(char *filename_){
	countElem = 0;
	curStr = 0;
	filename =  filename_;
}



// Добавление записи
void str_list::addStr(const WCHAR* str){
	WCHAR* tmp = wcsdup(str); 

	slist.push_back(tmp);
	++countElem;
}



// Загрузка из файла
int str_list::getByFile(void){
	DWORD cbRead;
    WCHAR stdPath[30] = TEXT("C:\\input.txt");
	
	HANDLE hFile = CreateFile(stdPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile ==  INVALID_HANDLE_VALUE){
		return -1;
	}

	DWORD bufSize = 0;
    bufSize = GetFileSize(hFile, NULL);
	if (bufSize == INVALID_FILE_SIZE){
		CloseHandle(hFile);
		return -1;
	}
	WCHAR *buf = new WCHAR[bufSize/sizeof(WCHAR)+1];
	buf[bufSize/sizeof(WCHAR)]=0;	

	int iResult = ReadFile(hFile, buf, bufSize, &cbRead, NULL);
	if((!iResult) || (cbRead != bufSize)){
		if (!buf) delete[] buf;
		CloseHandle(hFile);
		return -1;
	}

	parse(buf, bufSize);

	if (buf != NULL) delete[] buf;
	CloseHandle(hFile);
	return 0;
}




//void str_list::regComp(WCHAR *regExp){
//	WCHAR seps[] = L" \r\t\n";
//	WCHAR *token;
//	
//	token = wcstok(buf, seps);
//	
//	while( token != NULL ){
//		addStr(token);
//		token = wcstok( NULL, seps );
//	}
//}


// Парсинг строки
void str_list::parse(WCHAR *buf, DWORD bufSize){
	WCHAR seps[] = L" \r\t\n";
	WCHAR *token;
	
	token = wcstok(buf, seps);
	
	while( token != NULL ){
		addStr(token);
		token = wcstok( NULL, seps );
	}
}



// Получение строки
WCHAR* str_list::getStr(void){
	if (curStr == countElem){ 
		curStr = 0;
		return NULL;
	}
	std::list<WCHAR*>::iterator i = slist.begin();
	std::advance(i, curStr);
	curStr++;
	return *i;
}


// Удаление списка
str_list::~str_list(void){
	std::list<WCHAR*>::const_iterator it, it_begin = slist.begin(), it_end = slist.end();
	for (it = it_begin; it != it_end; ++it){ 
		if (*it){
			free(*it);
		}
	}
	slist.clear();
	countElem = 0;
}

