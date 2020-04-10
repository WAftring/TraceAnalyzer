#pragma once
#include <Windows.h>
enum LogType {
	HEADER,
	WARN,
	INFO
};


BOOL InitLogger(const char* Path);
VOID WriteToReport(char timestr[64], char* Content, LogType type);
