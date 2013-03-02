#pragma once
#include <stdio.h>
#include <iostream>
#include <Windows.h>
#include <Wininet.h>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/foreach.hpp>

typedef void (*ParserType)(const std::string&, boost::property_tree::ptree&);

// TODO: std::string -> std::wstring


class HSFTPHelper{
public:
	HSFTPHelper(void);
	
	static unsigned WINAPI mainFTPThread(void *call);
	void ParseConfig (const boost::property_tree::ptree& config);
	void ParseFile(const std::string& name, ParserType parser);
	
	int connect(void);
	int copyFile(std::string filename);
	int disconnect(void);
	virtual ~HSFTPHelper(void);

	
	BOOL SetCurrentDir(const std::wstring& dir);
	BOOL GetCurrentDir(std::wstring& dir);

	BOOL MkDir(const std::wstring& dir);
	BOOL UploadFile(const std::wstring& path); // local path
	BOOL DownloadFile(const std::wstring& path /* local */, const std::wstring& name /* remote */);
	BOOL DeleteFile(const std::wstring& name /* remote */);

private:
	HINTERNET hINet, hFTP;	
	int _isExit;
	int _waitTime;
	int _isSaveSession;
	int _isSaveOnFtp;
	std::string _ftpServer;
	int _ftpPort;
	std::string	_ftpLogin;
	std::string	_ftpPass;
	std::string	_outFilename;
	std::string	_inPathForSession;
	std::wstring _curFTPDir;
};

