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

#include <stdlib.h>

#include "line.h"

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printf("%s <executable> <args ...>\n", argv[0]);
        exit(1);
    }

    char* execargv[argc - 1];
    int i;
    for (i = 0; i < argc - 1; i++)
    {
        execargv[i] = argv[i + 1];
    }

    Line line;
    line.open(argv[1]);
    line.execute(argc - 1, execargv);
    return 0;
}

