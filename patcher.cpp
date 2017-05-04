
#include <stdlib.h>

#include "patcher.h"

using namespace std;

Patcher::Patcher(LineProcess* process) : Logger("Patcher")
{
    m_process = process;
}

Patcher::~Patcher()
{
}

bool Patcher::patch(uint64_t start)
{
    uint64_t end = 0;
    uint64_t ptr = start;

    if (
        (start >= IMAGE_BASE && start <= (IMAGE_BASE + 0xffffff)) ||
        (start >= 0x700000000000))
    {
        // Line binary or kernel
        return true;
    }
    if (isPatched(ptr))
    {
        log("patch: Code is already patched: 0x%llx", ptr);
        return true;
    }
    log("patch: Start: 0x%llx", ptr);

    PatchRange* range = new PatchRange();
    range->start = start;
    range->end = start + 1;
    m_patchRanges.push_back(range);

    while (true)
    {
        uint8_t* p = (uint8_t*)ptr;
        if (*p == 0xcc)
        {
            log("patch: found patch instruction! Abort!!");
            return false;
        }

        x86_insn_t insn;
        int size = 0;

        size = x86_disasm((unsigned char*)ptr, 0x10000, ptr, 0, &insn );
        if (size <= 0)
        {
            log("0x%llx: Invalid instruction", ptr);
            exit(255);
            return false;
        }

        range->end = ptr + size;

#if 0
        char line[4096];
        //int i;

        if (x86_format_insn(&insn, line, 4096, att_syntax) <= 0 )
        {
            log("0x%x: Unable to format instruction", ptr);
            exit(255);
            return false;
        }

        log("0x%llx: %s", ptr, line);
#endif

        if (insn.type == insn_return)
        {
            if (end < ptr)
            {
#ifdef DEBUG_PATCH
                log("patch: %p: Found end of function");
#endif
                break;
            }
        }
        else if (insn.type == insn_syscall)
        {
#ifdef DEBUG_PATCH
            log("patch: 0x%llx: Patching SYSCALL", ptr);
#endif
            patch(PATCH_SYSCALL, insn, ptr);
        }
        else if (insn.type == insn_jmp || insn.type == insn_jcc|| insn.type == insn_call)
        {
            const char* insntype;
            if (insn.type == insn_jmp || insn.type == insn_jcc)
            {
                insntype = "BRANCH";
            }
            else
            {
                insntype = "CALL";
            }

            //log("patch: 0x%llx: %s: operand_count=%d", ptr, insntype, insn.operand_count);
            x86_op_t* target = x86_get_branch_target(&insn);
            if (target->datatype != op_byte )
            {
                // FAR !
#ifdef DEBUG_PATCH
                log("patch: 0x%llx:  -> Patching %s...", ptr, insntype);
#endif
                patch(PATCH_CALL, insn, ptr);

                if (insn.type == insn_jmp && end < ptr)
                {
                    break;
                }
            }
            else
            {
                uint64_t destAddr = insn.addr + insn.size + target->data.sbyte;
#ifdef DEBUG_PATCH
                log("patch: 0x%llx: %s: near branch to 0x%llx", ptr, insntype, destAddr);
#endif
                if (end < destAddr)
                {
                    end = destAddr;
                }
                else if (destAddr < start)
                {
#ifdef DEBUG_PATCH
                    log("patch: Jump to 0x%llx is before this range");
#endif
                    bool patched = isPatched(destAddr);
#ifdef DEBUG_PATCH
                    log("patch:  -> isPatched=%d", patched);
#endif
                    if (!patched)
                    {
                        patch(destAddr);
                    }
                }
                else if (p[size] == 0 && p[size + 1] == 0)
                {
                    log("patch: FUNCTION END??");
                    break;
                }
            }
        }
        else if (insn.prefix & op_fs_seg)
        {
            if (insn.type != insn_nop)
            {
                log("patch: 0x%llx: Patching FS instruction", ptr);
                patch(PATCH_FS, insn, ptr);
            }
        }

        ptr += size;
    }

    log("patch: Patched range: 0x%llx-0x%llx", start, ptr);

    return true;
}

void Patcher::patch(PatchType type, x86_insn_t insn, uint64_t pos)
{
    uint8_t* p = (uint8_t*)pos;
    uint8_t original = *p;
    *p = 0xcc;
    Patch patch;
    patch.type = type;
    patch.insn = insn;
    patch.patchedByte = original;
    m_patches.insert(make_pair(pos, patch));
}

bool Patcher::isPatched(uint64_t ptr)
{
    std::vector<PatchRange*>::iterator it;
    for (it = m_patchRanges.begin(); it != m_patchRanges.end(); it++)
    {
        PatchRange* range = *it;
        if (ptr >= range->start && ptr < range->end)
        {
            return true;
        }
    }
    return false;
}

Patch* Patcher::getPatch(uint64_t patchedAddr)
{
    map<uint64_t, Patch>::iterator it;
    it = m_patches.find(patchedAddr);
    if (it == m_patches.end())
    {
        log("trap: Invalid patch!?");
        exit(255);
    }
    return &(it->second);
}

