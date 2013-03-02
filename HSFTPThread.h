#pragma once
#include "winsock2.h"
#include <Windows.h>
#include <process.h> 
#include <stdio.h>
#include "HSFTP.h"

class HSFTPThread{
public:
	HSFTPThread(void);
	int start(void);
	
	static unsigned WINAPI mainFTPThread(void *call);

	int stop(void);
	virtual ~HSFTPThread(void);
private:
	HANDLE hFTPThread;
	int _isExit;
};

