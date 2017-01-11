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

#ifndef __LINE_ELFLIBRARY_H_
#define __LINE_ELFLIBRARY_H_

#include "elfbinary.h"

#include <map>

class ElfExec;

class ElfLibrary : public ElfBinary
{
 protected:

 public:
    ElfLibrary(ElfExec* exec);
    virtual ~ElfLibrary();

    virtual void entry(int argc, char** argv, char** envp);
};

#endif
