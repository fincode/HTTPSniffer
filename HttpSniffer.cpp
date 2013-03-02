/************************************************
TO-DO:
	1. код						//	complete
	2. параметры в конфиг		//	complete
	3. виндовый сервис			//	complete
	4. инфа про интерфейсы		//	complete
	5. сделать инсталлятор		//	complete
	
************************************************/

#include "stdafx.h"
#include "HSWebTool.h"
#include <tchar.h>
#include <iostream>
#include <process.h>

#define THRD_TIMEOUT 20000

using namespace std;

void ServiceInstall();
void ServiceUnInstall();
void ServiceStart();
void ServiceStop();
void ServiceMain(DWORD argc, LPTSTR *argv); 
void ServiceCtrlHandler(DWORD nControlCode);
int StartServiceThread();
int UpdateServiceStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode,
	DWORD dwServiceSpecificExitCode, DWORD dwCheckPoint,
	DWORD dwWaitHint);
unsigned __stdcall  ServiceExecutionThread(void*);
void KillService();
void PrintError();

	HSWebTool sniffer;
wchar_t *strServiceName = L"HTTPSniffer";
SERVICE_STATUS_HANDLE nServiceStatusHandle; 
HANDLE killServiceEvent;

DWORD nServiceCurrentStatus;
HANDLE hServiceThread;

bool nServiceRunning;
int isService = 1;


// Остановка сниффинга
BOOL WINAPI HandlerRoutine(DWORD dwCtrlType)
{
	switch(dwCtrlType){ 
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
		nServiceRunning = false;
		break;
	} 

	return TRUE;
} 

int _tmain(int argc, _TCHAR* argv[])
{
	char HelpString[]="Usage: hssvc_r.exe -[start|stop|install|uninstall|console]\r\n";
	if (argc==2){
		if ((argv[1][0]==L'-') || (argv[1][0]==L'/')){
			if (lstrcmpi(&argv[1][1], L"service")==0){
				isService = 1;
				SERVICE_TABLE_ENTRY servicetable[]=
				{
					{strServiceName,(LPSERVICE_MAIN_FUNCTION)ServiceMain},
					{NULL,NULL}
				};
				if(!StartServiceCtrlDispatcher(servicetable)){
					PrintError();
				}
				return 0;
			} 
			if (lstrcmpi(&argv[1][1], L"start")==0){
				ServiceStart();
				return 0;
			}
			if (lstrcmpi(&argv[1][1], L"stop")==0){
				ServiceStop();
				return 0;
			}
			if (lstrcmpi(&argv[1][1], L"install")==0){
				ServiceInstall();
				return 0;
			}						
			if (lstrcmpi(&argv[1][1], L"uninstall")==0){
				ServiceUnInstall();
				return 0;
			}
			if (lstrcmpi(&argv[1][1], L"console")==0){
				isService = 0;
				SetConsoleCtrlHandler(HandlerRoutine, TRUE);
				StartServiceThread();
				return 0;
			}  
		}
		else{
			cout << HelpString;
			return 0;
		}
	}
	else{
		cout << HelpString;
		return 0;
	}
}

void ServiceMain(DWORD argc, LPTSTR *argv)
{
	nServiceStatusHandle=RegisterServiceCtrlHandler(strServiceName,
		(LPHANDLER_FUNCTION)ServiceCtrlHandler);
	if(!nServiceStatusHandle){
		return;
	}
	if(!UpdateServiceStatus(SERVICE_START_PENDING,NO_ERROR,0,1,3000)){
		return;
	}
	killServiceEvent=CreateEvent(0,TRUE,FALSE,0);
	if(killServiceEvent==NULL){
		return;
	}
	if(!UpdateServiceStatus(SERVICE_START_PENDING,NO_ERROR,0,2,1000)){
		return;
	}
	nServiceCurrentStatus=SERVICE_RUNNING;
	if(!UpdateServiceStatus(SERVICE_RUNNING,NO_ERROR,0,0,0)){
		return;
	}
	if(!StartServiceThread()){
		UpdateServiceStatus(SERVICE_STOPPED,NO_ERROR,0,0,0);
		return;
	}
	WaitForSingleObject(killServiceEvent,INFINITE);
	CloseHandle(killServiceEvent);
}



int UpdateServiceStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode,
	DWORD dwServiceSpecificExitCode, DWORD dwCheckPoint,
	DWORD dwWaitHint)
{
	SERVICE_STATUS nServiceStatus;
	nServiceStatus.dwServiceType=SERVICE_WIN32_OWN_PROCESS;
	nServiceStatus.dwCurrentState=dwCurrentState;
	if(dwCurrentState==SERVICE_START_PENDING){
		nServiceStatus.dwControlsAccepted=0;
	}
	else{
		nServiceStatus.dwControlsAccepted=SERVICE_ACCEPT_STOP			
			|SERVICE_ACCEPT_SHUTDOWN;
	}
	if(dwServiceSpecificExitCode==0){
		nServiceStatus.dwWin32ExitCode=dwWin32ExitCode;
	}
	else{
		nServiceStatus.dwWin32ExitCode=ERROR_SERVICE_SPECIFIC_ERROR;
	}
	nServiceStatus.dwServiceSpecificExitCode=dwServiceSpecificExitCode;
	nServiceStatus.dwCheckPoint=dwCheckPoint;
	nServiceStatus.dwWaitHint=dwWaitHint;

	if(!SetServiceStatus(nServiceStatusHandle,&nServiceStatus)){
		KillService();
		return false;
	}
	else
		return true;
}



BOOL StartServiceThread()
{	
	hServiceThread = (HANDLE)_beginthreadex(NULL,0,&ServiceExecutionThread,0,0,0);
	if(hServiceThread==0){ 
		return FALSE;
	}
	else{ 
		SetThreadPriority(hServiceThread,THREAD_PRIORITY_ABOVE_NORMAL); 
		nServiceRunning=true;
		DWORD dwWaitResult = WaitForSingleObject(hServiceThread,INFINITE); 
		return TRUE;
	}
}



unsigned __stdcall  ServiceExecutionThread(void*)
{
	if (sniffer.start(isService) == FALSE){
		getch();
		return FALSE;
	};
	fprintf(stdout,"Sniffing is runnig...\n(For stop sniffing press ctrl+c)\n\n");
	while(nServiceRunning){ 
		sniffer.runSniffing();
	}   	
	
	sniffer.stop();	
	return TRUE;
}



void KillService()
{
	nServiceRunning=false;
	SetEvent(killServiceEvent);
	UpdateServiceStatus(SERVICE_STOPPED,NO_ERROR,0,0,0);
}



void ServiceCtrlHandler(DWORD nControlCode)
{
	BOOL success;
	switch(nControlCode)
	{	
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP:
		nServiceCurrentStatus=SERVICE_STOP_PENDING;
		success=UpdateServiceStatus(SERVICE_STOP_PENDING,NO_ERROR,0,1,3000);
		KillService();		
		return;
	default:
		break;
	}
	UpdateServiceStatus(nServiceCurrentStatus,NO_ERROR,0,0,0);
}



void ServiceStart()
{
	SC_HANDLE schService;
	SC_HANDLE schSCManager;

	schSCManager=OpenSCManager(0,0,SC_MANAGER_CREATE_SERVICE);
	if(!schSCManager){
		PrintError();
		return;
	}
	schService=OpenService(schSCManager,strServiceName,SERVICE_START);
	if(!schService){
		PrintError();
		CloseServiceHandle(schSCManager);
		return;
	}
	if (!StartService(schService,0,NULL)){
		PrintError();
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}



void ServiceStop()
{
	SC_HANDLE schService;
	SC_HANDLE schSCManager;

	schSCManager=OpenSCManager(0,0,SC_MANAGER_CREATE_SERVICE);
	if(!schSCManager){		
		PrintError();
		return;
	}
	schService=OpenService(schSCManager,strServiceName,SERVICE_STOP);
	if(!schService){
		PrintError();
		CloseServiceHandle(schSCManager);
		return;
	}
	SERVICE_STATUS m_SERVICE_STATUS;
	if (!ControlService(schService,SERVICE_CONTROL_STOP,&m_SERVICE_STATUS))
		PrintError();
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}



void ServiceInstall()
{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;
	TCHAR szPath[MAX_PATH+9];

	if( !GetModuleFileName(NULL, szPath, MAX_PATH)){
		PrintError();
		return;
	}
	wcscat_s(szPath,MAX_PATH+9,L" -service");

	schSCManager=OpenSCManager(0,0,SC_MANAGER_CREATE_SERVICE);
	if(!schSCManager){
		PrintError();
		return;
	}

	schService=CreateService(schSCManager, strServiceName, L"HTTP Sniffer",
		SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL,szPath,
		0,0,0,0,0);
	if(!schService){
		PrintError();
		CloseServiceHandle(schSCManager);
		return;
	}
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}

void ServiceUnInstall()
{
	SC_HANDLE schService;
	SC_HANDLE schSCManager;

	schSCManager=OpenSCManager(0,0,SC_MANAGER_CREATE_SERVICE);
	if(!schSCManager){
		PrintError();
		return;
	}
	schService=OpenService(schSCManager,strServiceName,DELETE);
	if(!schService){
		PrintError();
		CloseServiceHandle(schSCManager);
		return;
	}
	if (!DeleteService(schService)){
		PrintError();
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}



void PrintError(void)
{
	void* cstr;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &cstr,
		0,
		NULL
	);
	LocalFree(cstr);
}