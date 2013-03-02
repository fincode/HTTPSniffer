#pragma once
#define HAVE_REMOTE
#include "pcap.h"								// Работа сниффера
#include "winsock2.h"							// Класс для работы с сокетами
#include "HSTcpPacket.h"						// Класс для работы с TCP-пакетами
#include "HSSavedSessionClass.h"				// Класс для работы с сохраненными сессиями
#include <boost/property_tree/ini_parser.hpp>	// Класс для парсинга
#include <IPHlpApi.h>							// Класс для работы с сетевыми устройствами

typedef void (*ParserType)(const std::string&, boost::property_tree::ptree&);

class HSWebTool{
public:
	HSWebTool(void);							// Инициализация параметров
	BOOL start(int isService);					// Запуск работы

	BOOL getDeviceList(void);					// Получить список устройств
	int printDeviceList(PIP_ADAPTER_INFO ptr_adapter_info);	// Печать списка устройств
	BOOL setCurrentDevice(int deviceCnt);		// Выбор сетевого устройства
	
	BOOL initDevice(void);						// Инициализация сетевого устройства
	BOOL setFilter(void);						// Установка фильтра
	BOOL setOutput(void);						// Установка выходного файла
	void setOutputName(void);					// Установка имени сессии

	void ParseConfig (const boost::property_tree::ptree& config);	// Парсинг конфига
	int ParseFile(const std::string& name, ParserType parser);		// Парсинг конфиг-файла
	BOOL initLogEvent(void);										// Запись в LogEvent
	void writeError(LPCTSTR text);


	BOOL runSniffing(void);						// Запуск сниффинга
	BOOL workWithPacket(void);					// Обработка пакетов
	BOOL getTcpPacket(int onlyPrintPacket);		// Обработка полученного TCP-пакета

	void stop(void);							// Остановка работы
	virtual ~HSWebTool(void);					// Освобождение ресурсов

private:
	char *_dev;									// Устройство для снифинга
	std::string _filter_exp;					// Выражение фильтра
	std::string _outFilename;					// Имя выходного файла
	std::string _outPathForSession;				// Имя выходного каталога
	char _errbuf[PCAP_ERRBUF_SIZE];				// Error string
	const u_char *_packet;						// Текущий пакет
	int _maxSizePacket;							// Максимальный размер пакета
	int _numPackets;							// Кол-во принимаемых пакетов
	int _timeout;								// Таймаут ожидания пакета
	int _findDataIn;							// Секция в пакете для поиска
	int _defualtDevice;							// Устройство по умолчанию
	int _isExit;								// Флаг остановки сниффинга
	int _isService;								// Флаг работы как сервиса
	int _isSaveSession;							// Сохранят сессии или пакеты
	int tcp,others,good,total;					// Полученные пакеты
	struct bpf_program _fp;						// Откомплированный фильтр
	struct pcap_pkthdr *_header;				// Хэдер пакета	
	HANDLE _hLog;
	
	FILE *_fstream;								// Выходной файл
	bpf_u_int32 _mask;							// Сетевая маска устройства
	bpf_u_int32 _net;							// IP-адрес устройства
	pcap_if_t *_alldevs;						// Список устройств						
	pcap_t *_handle;							// Handle сессии
	IPV4_HDR *_iphdr;							// IP-заголовок
	HSSavedSessionClass *_sessionList;			// Список сохраненных сессий
	HSStrList *_strList;						// Список слов
	std::string _inFilename;					// Имя входного файла
};