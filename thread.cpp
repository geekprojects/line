#include "thread.h"
#include "process.h"


LineThread::LineThread(LineProcess* process)
{
    m_process = process;

    pthread_cond_init(&m_processSignalCond, NULL);
    pthread_mutex_init(&m_processSignalCondMutex, NULL);
}

LineThread::~LineThread()
{
}

struct tramponlinedata
{
    LineThread* thread;
    int argc;
    char** argv;
    char** env;
};

static void* trampoline(void* args)
{
    tramponlinedata* data = (tramponlinedata*)args;
    data->thread->initialEntry(data->argc, data->argv, data->env);
    return NULL;
}

void LineThread::start(int argc, char** argv, char** env)
{
    tramponlinedata* data;
    data = new tramponlinedata();

    data->thread = this;
    data->argc = argc;
    data->argv = argv;
    data->env = env;

    // Create ELF Thread
    pthread_create(&m_pthread, NULL, trampoline, data);
}

void LineThread::initialEntry(int argc, char** argv, char** env)
{
    m_pthread = pthread_self();
    m_task = mach_thread_self();
    m_process->addThread(this);

    entry(argc, argv, env);
}

void LineThread::entry(int argc, char** argv, char** env)
{
    printf("LineThread::entry: Here!\n");
}

void LineThread::singleStep(bool enable)
{
    m_process->requestSingleStep(this, enable);
}

void LineThread::waitForProcess()
{
    pthread_cond_wait(&m_processSignalCond, &m_processSignalCondMutex);
}

void LineThread::signalFromProcess()
{
    pthread_cond_signal(&m_processSignalCond);
}

