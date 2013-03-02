#include "StdAfx.h"
#include "HSFTPThread.h"
#include <boost/property_tree/ini_parser.hpp>
#include <boost/foreach.hpp>
#include <boost/asio/detail/pop_options.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/detail/socket_types.hpp>
#include <boost/asio/detail/socket_ops.hpp>


HSFTPThread::HSFTPThread(void){
	hFTPThread = 0;
}



int HSFTPThread::start(void){
	hFTPThread = (HANDLE)_beginthreadex(NULL, 0, mainFTPThread, this, 0, NULL);
	if(hFTPThread==0){ 
		return -1;
	}
	else{ 
		SetThreadPriority(hFTPThread,THREAD_PRIORITY_ABOVE_NORMAL); 
		_isExit  = 0;
		WaitForSingleObject(hFTPThread,INFINITE);
		return 1;
	}
}



unsigned __stdcall HSFTPThread::mainFTPThread(void *call) {
	HSFTPThread *self = (HSFTPThread*)call;
	HSFTP ftpRec;

	MessageBox(NULL,L"Start FTP Record", L"OK", NULL);
	
	while(self->_isExit){
		if (ftpRec.connect() == -1){
			fprintf(stdout,"Can't connect to ftp\n");

		}
		else ftpRec.copyToFTP();
		Sleep(1000);
	}   	
	return 0;
}



int HSFTPThread::stop(void){
	_isExit = 1;
}


HSFTPThread::~HSFTPThread(void){
}
