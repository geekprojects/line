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

void MainThread::entry(int argc, char** argv, char** env)
{
    map<string, ElfLibrary*> libs = m_process->getExec()->getLibraries();
    //singleStep(true);

    m_process->getExec()->relocateLibrariesIFuncs();

    map<string, ElfLibrary*>::iterator it;
    for (it = libs.begin(); it != libs.end(); it++)
    {
        if (it->first != "libpthread.so.0")
        {
            it->second->entry(argc, argv, env);
        }
    }

    if (m_process->getLine()->getConfigTrace())
    {
        singleStep(true);
    }

    // Execute the ELF (Note, no Elves were harmed...)
    m_process->getExec()->entry(argc, argv, env);
}


