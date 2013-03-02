#include "StdAfx.h"
#include "HSFTPHelper.h"
#define READ_SIZE 32768 


HSFTPHelper::HSFTPHelper(void){
	ParseFile("config.ini", IniParser);
	hINet = NULL;
	SetCurrentDir(L"/");
}



BOOL HSFTPHelper::SetCurrentDir(const std::wstring& dir){
	return FtpSetCurrentDirectory(hFTP,dir.data());
}



BOOL HSFTPHelper::MkDir(const std::wstring& dir){
	return FtpCreateDirectory(hFTP, dir.data());
}



BOOL HSFTPHelper::DownloadFile(const std::wstring& path /* local */, const std::wstring& name /* remote */){
	return FtpGetFile(hFTP,name.data(),path.data(),FALSE,FILE_ATTRIBUTE_NORMAL,FTP_TRANSFER_TYPE_BINARY,NULL);
}



BOOL HSFTPHelper::DeleteFile(const std::wstring& name /* remote */){
	return FtpDeleteFile(hFTP, name.data());
}


BOOL HSFTPHelper::UploadFile(const std::wstring& path){ // local path
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hFTPFile = INVALID_HANDLE_VALUE;

	if (hFTP == NULL) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	hFile = CreateFile(path.data(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, NULL, 0);
	if (hFile ==  INVALID_HANDLE_VALUE){
		goto error;
	}

	hFTPFile = FtpOpenFile(hFTP,
				path.data(),			// Папка + имя файла, в которую закачиваем
				GENERIC_WRITE,
				FTP_TRANSFER_TYPE_BINARY,
				INTERNET_FLAG_RELOAD);
	
	if(hFTPFile == NULL){
		goto error;
	}
	// Считывание файла частями
	while(1){
		char buf[32768];
		buf[0] = 0;	
		DWORD dwReaded = 0;
		DWORD dwWrite = 0;
		// Считываем файл на локальной машине по 32кб
		if(ReadFile(hFile, buf, READ_SIZE, &dwReaded, NULL) != 0) {
			if(dwReaded != 0){
				// Записываем считанные 32кб на FTP
				if (!(InternetWriteFile(hFTPFile, buf, dwReaded, &dwWrite) && dwWrite == dwReaded)){
					goto error;
				}
			} else break;
		}
	}
	return TRUE;
error:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (hFTPFile != NULL)
		InternetCloseHandle(hFTPFile);
	return FALSE;
}



// Парсинг конфига
void HSFTPHelper::ParseConfig(const boost::property_tree::ptree& config){
	try{
		const boost::property_tree::ptree& main = config.get_child("main");
		_isSaveSession = main.get("saveSession", 0);
		
		_isSaveOnFtp = main.get("isSaveOnFtp", 0);
		_ftpServer = main.get<std::string>("ftpServer","127.0.0.1");
		_ftpPort = main.get("ftpPort", 21);
		_waitTime = main.get("waitTime", 60000);
		_ftpLogin = main.get<std::string>("ftpLogin", "admin");
		_ftpPass = main.get<std::string>("ftpPass", "123");

		_inFilename = main.get<std::string>("outFilename","C:/output.txt");
		_inPathForSession = main.get<std::string>("outPathForSession","C:/output/");
	}
	catch (const boost::property_tree::ptree_bad_data& error){
		std::cout << "Bad data: " << error.what() << std::endl;
	}
	catch (const boost::property_tree::ptree_bad_path& error){
		std::cout << "Bad path: " << error.what() << std::endl;
	}
}



// Парсинг файла
void HSFTPHelper::ParseFile(const std::string& name, ParserType parser){
	boost::property_tree::ptree config;
	parser(name, config);
	ParseConfig(config);
}



// Парсинг INI-файла
void IniParser(const std::string& name, boost::property_tree::ptree& config){
	boost::property_tree::read_ini(name, config);
}



// Соединение с сервером
int HSFTPHelper::connect(void){
	if((hINet = InternetOpenA(" ", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0)) == NULL) {
		return -1;
	}
	if((hFTP = InternetConnectA(hINet, _ftpServer.data(), _ftpPort, _ftpLogin.data(), _ftpPass.data(),
								INTERNET_SERVICE_FTP, 0, NULL)) == NULL) {
		InternetCloseHandle(hINet);
		return -1;
	}
    return 0;
}



// Копирование на фтп
int HSFTPHelper::copyToFTP(void){
	HANDLE hFile;
	if (_isSaveSession){
		LPWIN32_FIND_DATAA fileInfo;
		HANDLE curFile = 0;
		_inPathForSession.append("*.txt");
		curFile = FindFirstFileA(_inPathForSession.data(), fileInfo);	// Строка содержащая путь для поиска файлов.
		if (curFile == NULL) 
			return 0;	
		copyFile(fileInfo->cFileName);
		while (FindNextFileA(fileInfo, fileInfo)){
			copyFile(fileInfo->cFileName);
		}
		FindClose(curFile);
		CloseHandle(curFile);
		return 1;
	}
	copyFile(_inFilename.data());
	return 1;
}



HSFTPHelper::~HSFTPHelper(void){
	if (hINet != NULL) InternetCloseHandle(hINet);
	if (hFTP != NULL) InternetCloseHandle(hFTP);
}
