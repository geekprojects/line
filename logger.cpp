
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>

#include "logger.h"

LoggerWriter g_loggerWriter;

LoggerWriter::LoggerWriter()
{
    pid_t pid = getpid();

    char filename[1024];
    sprintf(filename, "trace_%d.log", pid);
    m_log = fopen(filename, "w");
    //fprintf(m_log, "Executable: %s\n", m_process->getExec()->getPath());
    //fflush(m_log);
}

LoggerWriter::~LoggerWriter()
{
    fclose(m_log);
}

void LoggerWriter::write(LoggerLevel level, const char* system, const char* format, va_list va)
{
    char buf[4096];
    vsnprintf(buf, 4096, format, va);

    char timeStr[256];
    time_t t;
    struct tm *tm;
    t = time(NULL);
    tm = localtime(&t);
    strftime(timeStr, 256, "%Y/%m/%d %H:%M:%S", tm);

const char* levelStr = "";
switch (level)
{
case LOG_DEBUG: levelStr = "DEBUG"; break;
case LOG_INFO: levelStr = "INFO"; break;
case LOG_WARN: levelStr = "WARN"; break;
case LOG_ERROR: levelStr = "ERROR"; break;
};

    pid_t pid = getpid();

    fprintf(m_log, "%s: %d: %s: %s: %s\n", timeStr, pid, levelStr, system, buf);
    fflush(m_log);

if (level == LOG_ERROR)
{
    fprintf(stderr, "%s: %d: %s: %s: %s\n", timeStr, pid, levelStr, system, buf);
}
}

Logger::Logger(const char* system)
{
    m_system = system;
}

Logger::~Logger()
{
}


void Logger::log(const char* format, ...)
{
    va_list va;
    va_start(va, format);

    g_loggerWriter.write(LOG_INFO, m_system, format, va);
}

void Logger::warn(const char* format, ...)
{
    va_list va;
    va_start(va, format);

    g_loggerWriter.write(LOG_WARN, m_system, format, va);
}

void Logger::error(const char* format, ...)
{
    va_list va;
    va_start(va, format);

    g_loggerWriter.write(LOG_ERROR, m_system, format, va);
}


