#pragma once
#include <Windows.h>
enum LogType {
	HEADER,
	WARN,
	INFO
};


BOOL InitLogger(const char* Path);
VOID WriteToReport(char* Content, LogType type);
