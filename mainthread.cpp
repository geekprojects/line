#include "mainthread.h"
#include "process.h"
#include "elflibrary.h"

using namespace std;

extern char **environ;

MainThread::MainThread(LineProcess* process)
    : LineThread(process)
{
}

MainThread::~MainThread()
{
}

void MainThread::entry(int argc, char** argv)
{
    map<string, ElfLibrary*> libs = m_process->getExec()->getLibraries();
printf("MainThread::entry: Here, setting single step...\n");
    singleStep();
printf("MainThread::entry: Single Step!\n");

    m_process->getExec()->relocateLibrariesIFuncs();

    map<string, ElfLibrary*>::iterator it;
    for (it = libs.begin(); it != libs.end(); it++)
    {
        if (it->first != "libpthread.so.0")
        {
            it->second->entry(argc, argv, environ);
        }
    }

    // Execute the ELF (Note, no Elves were harmed...)
    m_process->getExec()->entry(argc, argv, environ);
}


