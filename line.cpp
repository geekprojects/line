/*
 * line - Line Is Not an Emulator
 * Copyright (C) 2016 GeekProjects.com
 *
 * This file is part of line.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#include "line.h"
#include "process.h"
#include "utils.h"

#include <sys/param.h>

using namespace std;

#define X86_EFLAGS_T 0x100UL

Line::Line() : Logger("Line"), m_kernel(this)
{
    m_configTrace = false;
    m_configForked = false;
    m_elfBinary = NULL;
    m_process = NULL;

    const char* homechar = getenv("OSXHOME");
    if (homechar == NULL)
    {
        homechar = getenv("HOME");
    }
    string home = string(homechar);
    m_containerBase = home + "/Library/Application Support/Line/default";

    string logDir = m_containerBase + "/logs";
    LoggerWriter::init(logDir);

    m_config.load(m_containerBase);

    m_kernel.getFileSystem()->init(&m_config);
}

Line::~Line()
{
}

bool Line::open(const char* execpath)
{
    bool res;

    log("open: executable: %s", execpath);

    char* linuxExec = m_kernel.getFileSystem()->path2osx(execpath);

    int a = -1;
    if (linuxExec != NULL)
    {
        a = access(linuxExec, F_OK | X_OK);
    }

    if (a != 0)
    {
        error("unable to find executable: %s -> %s", execpath, linuxExec);
        return false;
    }

    m_elfBinary = new ElfExec(this);
    res = m_elfBinary->load(linuxExec);
    if (!res)
    {
        return false;
    }

    return true;
}

bool Line::execute(int argc, char** argv)
{
    m_process = new LineProcess(this, m_elfBinary);
    m_kernel.setProcess(m_process);

    int i;
    for (i = 0; i < argc; i++)
    {
        log("execute: arg %d: %s", i, argv[i]);
    }

    bool res;
    res = m_elfBinary->map();
    if (!res)
    {
        exit(1);
    }

    res = m_elfBinary->loadLibraries();
    if (!res)
    {
        exit(1);
    }

    m_process->start(argc, argv);

    return true;
}

