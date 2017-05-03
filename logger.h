#ifndef __LINE_LOGGER_H_
#define __LINE_LOGGER_H_

#include <stdio.h>

enum LoggerLevel
{
    DEBUG,
    INFO,
    WARN,
    ERROR,
};

class LoggerWriter
{
 private:
    FILE* m_log;

 public:
    LoggerWriter();
    ~LoggerWriter();

    void write(LoggerLevel level, const char* system, const char* __format, va_list ap);
};

class Logger
{
 private:
    const char* m_system;

 public:
    Logger(const char* system);
    ~Logger();

    void log(const char* __format, ...); // INFO
    void logv(const char* __format, va_list ap);
    void warn(const char* __format, ...);
    void error(const char* __format, ...);
};

#endif
