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
#include <ctype.h>

void hexdump(const char* pos, int len)
{
    int i;
    for (i = 0; i < len; i += 16)
    {
        int j;
        printf("%08llx: ", (uint64_t)(pos + i));
        for (j = 0; j < 16 && (i + j) < len; j++)
        {
            printf("%02x ", (uint8_t)pos[i + j]);
        }
        for (j = 0; j < 16 && (i + j) < len; j++)
        {
            char c = pos[i + j];
            if (!isprint(c))
            {
                c = '.';
            }
            printf("%c", c);
        }
        printf("\n");
    }
}

