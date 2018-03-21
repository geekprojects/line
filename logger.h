#ifndef __LINE_LOGGER_H_
#define __LINE_LOGGER_H_

#include <stdio.h>

#include <string>

enum LoggerLevel
{
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
};

class LoggerWriter
{
 private:
    std::string m_logDir;
    FILE* m_log;

    void setLogDir(std::string logDir);

 public:
    LoggerWriter();
    virtual ~LoggerWriter();

    void write(LoggerLevel level, const char* system, const char* __format, va_list ap);

    static void init(std::string logDir);
};

class Logger
{
 private:
    const char* m_system;

 public:
    Logger(const char* system);
    virtual ~Logger();

    void log(const char* __format, ...); // INFO
    void logv(const char* __format, va_list ap);
    void warn(const char* __format, ...);
    void error(const char* __format, ...);
};

#endif
