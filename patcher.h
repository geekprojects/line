#ifndef __LINE_PATCHER_H_
#define __LINE_PATCHER_H_

#include <stdint.h>

#include <map>
#include <vector>

#include <libdis.h>

#include "logger.h"

class LineProcess;

enum PatchType
{
    PATCH_CALL,
    PATCH_SYSCALL,
    PATCH_FS
};

struct Patch
{
    PatchType type;
    x86_insn_t insn;
    uint8_t patchedByte;
};

struct PatchRange
{
    uint64_t start;
    uint64_t end;
};

class Patcher : Logger
{
 private:
    LineProcess* m_process;

    std::map<uint64_t, Patch> m_patches;
    std::vector<PatchRange*> m_patchRanges;

    void patch(PatchType type, x86_insn_t insn, uint64_t pos);

 public:
    Patcher(LineProcess* process);
    virtual ~Patcher();

    bool patch(uint64_t ptr);

    Patch* getPatch(uint64_t ptr);

    PatchRange* findPatchRange(uint64_t ptr);
    bool isPatched(uint64_t ptr);
};

#endif
