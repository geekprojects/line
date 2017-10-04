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

#ifndef __LINE_H_
#define __LINE_H_

#include <pthread.h>

#include "elfexec.h"
#include "logger.h"
#include "kernel.h"
#include "config.h"

class LineProcess;

class Line : Logger
{
 private:
    LinuxKernel m_kernel;
    std::string m_containerBase;
    Config m_config;

    ElfExec* m_elfBinary;
    LineProcess* m_process;

    bool m_configTrace;
    bool m_configForked;

 public:
    Line();
    ~Line();

    bool open(const char* elfpath);

    bool execute(int argc, char** argv);

    std::string getContainerBase() { return m_containerBase; }
    Config* getConfig() { return &m_config; }
    void setConfigTrace(bool trace) { m_configTrace = trace; }
    bool getConfigTrace() { return m_configTrace; }
    void setConfigForked(bool v) { m_configForked = v; }
    bool getConfigForked() { return m_configForked; }

    ElfExec* getElfBinary() { return m_elfBinary; }
    LineProcess* getProcess() { return m_process; }
    LinuxKernel* getKernel() { return &m_kernel; }
};


#endif
