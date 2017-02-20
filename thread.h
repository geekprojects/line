#ifndef __LINE_THREAD_H_
#define __LINE_THREAD_H_

#include <pthread.h>

class LineProcess;

class LineThread
{
 private:
    pthread_t m_pthread;

    pthread_cond_t m_processSignalCond;
    pthread_mutex_t m_processSignalCondMutex;

 protected:
    LineProcess* m_process;

 public:
    LineThread(LineProcess* process);
    virtual ~LineThread();

    void setPThread(pthread_t pthread) { m_pthread = pthread; }
    pthread_t getPThread() { return m_pthread; }

    void start(int argc, char** argv);
    void initialEntry(int argc, char** argv);
    virtual void entry(int argc, char** argv);

    void singleStep();

    void waitForProcess();
    void signalFromProcess();
};

#endif
