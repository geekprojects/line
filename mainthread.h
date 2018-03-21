#ifndef __LINE_INIT_THREAD_H_
#define __LINE_INIT_THREAD_H_

#include "thread.h"

class MainThread : public LineThread
{
 private:

 public:
    MainThread(LineProcess* process);
    virtual ~MainThread();

    virtual void entry(int argc, char** argv, char** environ);
};

#endif
