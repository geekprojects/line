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
#include <string.h>
#include <i386/eflags.h>

#include "elfprocess.h"

#define FETCH_NEXT() *(m_rip++)
#define FETCH_NEXT32() *(m_rip++)
#define FETCH_MODRM() {uint8_t modrm = FETCH_NEXT(); mod = (modrm >> 7) & 0x3; rm = modrm & 7; reg = (modrm >> 3) & 7; }

bool ElfProcess::execFSInstruction(uint8_t* rip, ucontext_t* ucontext)
{
    m_rip = rip;

    uint8_t next = FETCH_NEXT();
#if 0
    printf("ElfProcess::execFSInstruction: next=0x%x\n", next);
#endif

    bool rexW = false;
    bool rexR = false;
    bool rexX = false;
    bool rexB = false;

    if ((next & 0xf0) == 0x40)
    {
        rexW = (next >> 3) & 1;
        rexR = (next >> 2) & 1;
        rexX = (next >> 1) & 1;
        rexB = (next >> 0) & 1;

        next = FETCH_NEXT();
#if 0
        printf("ElfProcess::execFSInstruction:  -> REX prefix: W=%d, R=%d, X=%d, B=%d\n", rexW, rexR, rexX, rexB);
        printf("ElfProcess::execFSInstruction: next=0x%x\n", next);
#endif
    }

    int mod = 0;
    int rm = 0;
    int reg = 0;

    if (next == 0x33) // XOR
    {
        FETCH_MODRM();
#if 0
        printf("ElfProcess::execFSInstruction: XOR: modrm: mod=%x, rm=%x, reg=%x\n", mod, rm, reg);
#endif
        int64_t addr = fetchModRMAddress(mod, rm, rexB, ucontext);

        uint64_t value1 = readFS64(addr);

        uint64_t value2 = readRegister(reg, rexR, 32, ucontext);
        if (addr == 0x30)
        {
            value1 = 0;
        }

#if 0
        printf("ElfProcess::execFSInstruction: XOR %%fs:0x%llx(0x%llx), reg%d(0x%llx)\n", addr, value1, reg, value2);
#endif
        value1 ^= value2;
#if 0
        printf("ElfProcess::execFSInstruction: XOR  -> 0x%llx\n", value1);
#endif
        writeRegister(reg, rexR, 32, value1, ucontext);
    }
    else if (next == 0x83) // MOV r/m, reg -> r/m, %fs:offset
    {
        FETCH_MODRM();
#if 0
        printf("ElfProcess::execFSInstruction: Arithmetic: modrm: mod=%x, rm=%x, reg=%x\n", mod, rm, reg);
#endif
        int64_t addr = fetchModRMAddress(mod, rm, rexB, ucontext);
        switch (reg)
        {
            case 7:
            {

                int8_t cmpValue = fetch8();
                int64_t fsValue = readFS64(addr);
#if 0
                printf("ElfProcess::execFSInstruction: CMP $0x%x, fs:0x%llx: %d - %lld\n", cmpValue, addr, cmpValue, fsValue);
#endif

                int diff = cmpValue - fsValue;
                if (diff == 0)
                {
                    ucontext->uc_mcontext->__ss.__rflags &= ~(EFL_CF | EFL_PF | EFL_SF);
                    ucontext->uc_mcontext->__ss.__rflags |= EFL_ZF;
                }
                else
                {
                    printf("ElfProcess::execFSInstruction: CMP: Unhandled comparison! diff=%d\n", diff);
exit(0);
                }

            } break;

            default:
                printf("ElfProcess::execFSInstruction: Unhandled op: reg=0x%x\n", reg);
                exit(1);
        }
    }
    else if (next == 0x89) // MOV r/m, reg -> r/m, %fs:offset
    {
#if 0
        printf("ElfProcess::execFSInstruction: MOV\n");
#endif

        FETCH_MODRM();
#if 0
        printf("ElfProcess::execFSInstruction: modrm: mod=%x, rm=%x, reg=%x\n", mod, rm, reg);
#endif
        int64_t addr = fetchModRMAddress(mod, rm, rexB, ucontext);

        uint64_t value = readRegister(reg, rexR, 32, ucontext);
#if 0
        printf("ElfProcess::execFSInstruction: mov %%reg(%d = 0x%llx), %%fs:0x%llx (%lld)\n", reg, value, addr, addr);
#endif
        writeFS64((int)addr, value);
    }
    else if (next == 0x8b) // MOV %fs:offset, %reg
    {

        FETCH_MODRM();
#if 0
        printf("ElfProcess::execFSInstruction: MOV(8b): modrm: mod=%x, rm=%x, reg=%x\n", mod, rm, reg);
#endif
        int64_t addr = fetchModRMAddress(mod, rm, rexB, ucontext);
        uint64_t value = readFS64(addr);

        // HACK HACK HACK
        if (addr == -80 && value == 0)
        {
            value = 0x6b5b20;
        }

#if 0
        printf("ElfProcess::execFSInstruction: MOV(8b): MOV %%fs:%lld (0x%llx), r%d\n", addr, value, reg);
#endif
        writeRegister(reg, rexR, 64, value, ucontext);
    }
    else if (next == 0xc7) // MOV imm, %fs:mod/rm
    {
        FETCH_MODRM();
#if 0
        printf("ElfProcess::execFSInstruction: modrm: mod=%x, rm=%x, reg=%x\n", mod, rm, reg);
#endif
        int64_t addr = fetchModRMAddress(mod, rm, rexB, ucontext);

        int32_t value = fetch32();
#if 0
        printf("ElfProcess::execFSInstruction: value=0x%x\n", value);

        printf("ElfProcess::execFSInstruction: MOV $0x%x, fs:(addr=0x%lld)\n", value, addr);
#endif

        writeFS64(addr, value);
    }
    else
    {
        printf("ElfProcess::execFSInstruction: Unhandled opcode: 0x%x\n", next);
        exit(1);
    }

#if 0
    printf("ElfProcess::execFSInstruction: Done! Advancing to %p\n", m_rip);
#endif
    ucontext->uc_mcontext->__ss.__rip = (uint64_t)m_rip;

    return true;
}

uint64_t ElfProcess::fetchModRMAddress(int mod, int rm, int rexB, ucontext_t* ucontext)
{
    int64_t value = 0;
    if (rm == 0x4)
    {
        value = fetchSIB(rexB, ucontext);
    }
    else
    {
        value = readRegister(rm, rexB, 64, ucontext);
#if 0
        printf("ElfProcess::fetchModRMAddress: value=0x%llx\n", value);
#endif
    }
    switch (mod)
    {
        case 0:
            break;
        case 1:
            value += fetch8();
            break;
        case 2:
            value += fetch32();
            break;
        default:
            printf("ElfProcess::fetchModRMAddress: Unhandled Mod: 0x%x\n", mod);
            exit(1);
            break;
    }
    return value;
}

uint64_t ElfProcess::fetchSIB(int rexB, ucontext_t* ucontext)
{
    uint8_t sib = FETCH_NEXT();
    int base = sib & 7;
    int index = (sib >> 3) & 7;
    int scale = (sib >> 5) & 3;
#if 0
    printf("ElfProcess::fetchSIB: sib=0x%x, base=%d, index=%d, scale=%d\n", sib, base, index, scale);
#endif
    uint64_t value = 0;
    if (base != 5)
    {
        value = readRegister(base, rexB, 32, ucontext);
    }
    else
    {
        value = fetch32();
    }
#if 0
    printf("ElfProcess::fetchSIB: Base value: 0x%llx\n", value);
#endif

    uint64_t indexValue = 0;
    if (index != 4)
    {
        indexValue = readRegister(index, rexB, 32, ucontext);
    }
    else
    {
        indexValue = 0;
    }
    indexValue *= scale;
#if 0
    printf("ElfProcess::fetchSIB: Index value: 0x%llx\n", indexValue);
#endif
    if (indexValue != 0)
    {
        printf("ElfProcess::fetchSIB: TODO: indexValue is not 0\n");
        exit(0);
    }
    return value;
}

uint64_t ElfProcess::readRegister(int reg, int rexB, int size, ucontext_t* ucontext)
{
    uint64_t value = 0;
    if (rexB == 0)
    {
        const char* regname = "?";
        switch (reg)
        {
            case 0:
                regname = "AX";
                value = ucontext->uc_mcontext->__ss.__rax;
                break;

            case 1:
                regname = "CX";
                value = ucontext->uc_mcontext->__ss.__rcx;
                break;

            case 2:
                regname = "DX";
                value = ucontext->uc_mcontext->__ss.__rdx;
                break;

            case 3:
                regname = "BX";
                value = ucontext->uc_mcontext->__ss.__rbx;
                break;

            case 4:
                regname = "SP";
                value = ucontext->uc_mcontext->__ss.__rsp;
                break;

            case 5:
                regname = "BP";
                value = ucontext->uc_mcontext->__ss.__rbp;
                break;

            case 6:
                regname = "SI";
                value = ucontext->uc_mcontext->__ss.__rsi;
                break;

            case 7:
                regname = "DI";
                value = ucontext->uc_mcontext->__ss.__rdi;
                break;
        }
#if 0
        printf("ElfProcess::readRegister: reg=%s\n", regname);
#endif
    }
    else
    {
        printf("ElfProcess::readRegister: Unhandled: rexB == 1\n");
        exit(1);
    }

    bool neg = (value >> 63);
    if (size == 32)
    {
        if (neg)
        {
            value |= 0xffffffff00000000;
        }
        else
        {
            value &= 0xffffffff;
        }
    }
    else if (size == 16)
    {
        value &= 0xffff;
        if (neg)
        {
            value |= 0xffffffff00000000;
        }
    }

    return value;
}

void ElfProcess::writeRegister(int reg, int rexB, int size, uint64_t value, ucontext_t* ucontext)
{
    const char* regname = "?";
    if (rexB == 0)
    {
        switch (reg)
        {
            case 0:
                regname = "AX";
                ucontext->uc_mcontext->__ss.__rax = value;
                break;

            case 1:
                regname = "CX";
                ucontext->uc_mcontext->__ss.__rcx = value;
                break;

            case 2:
                regname = "DX";
                ucontext->uc_mcontext->__ss.__rdx = value;
                break;

            case 3:
                regname = "BX";
                ucontext->uc_mcontext->__ss.__rbx = value;
                break;
            case 4:
                regname = "SP";
                ucontext->uc_mcontext->__ss.__rsp = value;
                break;

            case 5:
                regname = "BP";
                ucontext->uc_mcontext->__ss.__rbp = value;
                break;

            case 6:
                regname = "SI";
                ucontext->uc_mcontext->__ss.__rsi = value;
                break;

            case 7:
                regname = "DI";
                ucontext->uc_mcontext->__ss.__rdi = value;
                break;
        }
    }
    else
    {
        switch (reg)
        {
            case 0:
                regname = "R8";
                ucontext->uc_mcontext->__ss.__r8 = value;
                break;

            case 1:
                regname = "R9";
                ucontext->uc_mcontext->__ss.__r9 = value;
                break;

            case 2:
                regname = "R10";
                ucontext->uc_mcontext->__ss.__r10 = value;
                break;

            case 3:
                regname = "R11";
                ucontext->uc_mcontext->__ss.__r11 = value;
                break;
            case 4:
                regname = "R12";
                ucontext->uc_mcontext->__ss.__r12 = value;
                break;

            case 5:
                regname = "R13";
                ucontext->uc_mcontext->__ss.__r13 = value;
                break;

            case 6:
                regname = "R14";
                ucontext->uc_mcontext->__ss.__r14 = value;
                break;

            case 7:
                regname = "R15";
                ucontext->uc_mcontext->__ss.__r15 = value;
                break;
        }
    }
#if 0
        printf("ElfProcess::writeRegister: %s\n", regname);
#endif
}

uint8_t ElfProcess::fetch8()
{
    return *(m_rip++);
}

uint32_t ElfProcess::fetch32()
{
    uint32_t value = 0;
    value |= fetch8();
    value |= fetch8() << 8;
    value |= fetch8() << 16;
    value |= fetch8() << 24;
    return value;
}

