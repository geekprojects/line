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

class Line
{
 private:
    ElfExec m_elfBinary;

    bool m_configTrace;

 public:
    Line();
    ~Line();

    bool open(const char* elfpath);

    bool execute(int argc, char** argv);

    void setConfigTrace(bool trace) { m_configTrace = trace; }
    bool getConfigTrace() { return m_configTrace; }

    ElfExec* getElfBinary() { return &m_elfBinary; }
};


#endif
