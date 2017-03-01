#ifndef __LINE_THREAD_H_
#define __LINE_THREAD_H_

#include <pthread.h>
#include <mach/mach_port.h>
#include <mach/mach_init.h>

class LineProcess;

class LineThread
{
 private:
    pthread_t m_pthread;
    task_t m_task;

    pthread_cond_t m_processSignalCond;
    pthread_mutex_t m_processSignalCondMutex;

 protected:
    LineProcess* m_process;

 public:
    LineThread(LineProcess* process);
    virtual ~LineThread();

    void setPThread(pthread_t pthread) { m_pthread = pthread; }
    pthread_t getPThread() { return m_pthread; }
    task_t getTask() { return m_task; }

    void start(int argc, char** argv);
    void initialEntry(int argc, char** argv);
    virtual void entry(int argc, char** argv);

    void singleStep(bool enable);

    void waitForProcess();
    void signalFromProcess();
};

#endif
