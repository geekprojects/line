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

#ifndef __ELF_H
#define __ELF_H

#include <sys/types.h>
#include <stdint.h>

#define EI_NIDENT		16
#define EI_MAG0			0
#define EI_MAG1			1
#define EI_MAG2			2
#define EI_MAG3			3
#define EI_CLASS		4
#define EI_DATA			5
#define EI_VERSION		6
#define EI_OSABI		7

#define ELFMAG0			0x7f
#define ELFMAG1			'E'
#define ELFMAG2			'L'
#define ELFMAG3			'F'

#define ELFCLASS32		1
#define ELFCLASS64		2

#define ELFDATA2LSB		1
#define ELFDATA2MSB		2

#define ET_REL			1
#define ET_EXEC			2
#define ET_DYN			3
#define ET_CORE			4

#define EM_M32			1
#define EM_SPARC		2
#define EM_386			3
#define EM_68K			4
#define EM_88K			5
#define EM_860			7
#define EM_MIPS			8
#define EM_X86_64		62

#define PT_LOAD			1
#define PT_DYNAMIC		2
#define PT_INTERP		3
#define PT_NOTE			4
#define PT_SHLIB		5
#define PT_PHDR			6
#define PT_TLS			7

#define PF_X			0x01
#define PF_W			0x02
#define PF_R			0x04

#define SHT_NULL		0
#define SHT_PROGBITS		1
#define SHT_SYMTAB		2
#define SHT_STRTAB		3
#define SHT_RELA		4
#define SHT_HASH		5
#define SHT_DYNAMIC		6
#define SHT_NOTE		7
#define SHT_NOBITS		8
#define SHT_REL			9
#define SHT_SHLIB		10
#define SHT_DYNSYM		11

#define SHF_WRITE		0x01
#define SHF_ALLOC		0x02
#define SHF_EXECINSTR		0x04

#define STN_UNDEF		0

#define ELF64_ST_BIND(I) ((I) >> 4)
#define ELF64_ST_TYPE(I) ((I) & 0x0f)
#define ELF64_ST_INFO(B, T) (((B) << 4) + ((T) & 0x0f))

#define STB_LOCAL		0
#define STB_GLOBAL		1
#define STB_WEAK		2

#define STT_NOTYPE		0
#define STT_OBJECT		1
#define STT_FUNC		2
#define STT_SECTION		3
#define STT_FILE		4
#define STT_GNU_IFUNC   10              /* Symbol is indirect code object */

#define SHN_UNDEF		0
/* 
 * These two are from FreeBSD 3.1 /usr/include/sys/elf_common.h 
 */
#define SHN_ABS			0xfff1
#define SHN_COMMON		0xfff2

#define ELF64_R_SYM(i)                  ((i) >> 32)
#define ELF64_R_TYPE(i)                 ((i) & 0xffffffff)

/* AMD x86-64 relocations.  */
#define R_X86_64_NONE           0       /* No reloc */
#define R_X86_64_64             1       /* Direct 64 bit  */
#define R_X86_64_PC32           2       /* PC relative 32 bit signed */
#define R_X86_64_GOT32          3       /* 32 bit GOT entry */
#define R_X86_64_PLT32          4       /* 32 bit PLT address */
#define R_X86_64_COPY           5       /* Copy symbol at runtime */
#define R_X86_64_GLOB_DAT       6       /* Create GOT entry */
#define R_X86_64_JUMP_SLOT      7       /* Create PLT entry */
#define R_X86_64_RELATIVE       8       /* Adjust by program base */
#define R_X86_64_GOTPCREL       9       /* 32 bit signed PC relative
                                           offset to GOT */
#define R_X86_64_DTPMOD64       16      /* ID of module containing symbol */
#define R_X86_64_DTPOFF64       17      /* Offset in module's TLS block */
#define R_X86_64_TPOFF64        18      /* Offset in initial TLS block */
#define R_X86_64_IRELATIVE      37      /* Adjust indirectly by program base */

#define DT_NULL     0
#define DT_NEEDED   1
#define DT_PLTRELSZ 2
#define DT_PLTGOT   3
#define DT_HASH     4
#define DT_STRTAB   5
#define DT_SYMTAB   6
#define DT_RELA     7
#define DT_RELASZ   8
#define DT_RELAENT  9
#define DT_STRSZ    10
#define DT_SYMENT   11
#define DT_INIT     12
#define DT_FINI     13
#define DT_SONAME   14
#define DT_JMPREL       23              /* Address of PLT relocs */

typedef uint64_t   Elf64_Addr;
typedef uint16_t   Elf64_Half;
typedef int16_t   Elf64_SHalf;
typedef uint64_t   Elf64_Off;
typedef int32_t   Elf64_Sword;
typedef uint32_t   Elf64_Word;
typedef uint64_t   Elf64_Xword;
typedef int64_t   Elf64_Sxword;
typedef Elf64_Half Elf64_Versym;

typedef uint32_t Elf_Symndx;

typedef struct elf64_hdr {
  unsigned char e_ident[EI_NIDENT];     /* ELF "magic number" */
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr e_entry;           /* Entry point virtual address */
  Elf64_Off e_phoff;            /* Program header table file offset */
  Elf64_Off e_shoff;            /* Section header table file offset */
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct elf64_phdr {
  Elf64_Word p_type;
  Elf64_Word p_flags;
  Elf64_Off p_offset;           /* Segment file offset */
  Elf64_Addr p_vaddr;           /* Segment virtual address */
  Elf64_Addr p_paddr;           /* Segment physical address */
  Elf64_Xword p_filesz;         /* Segment size in file */
  Elf64_Xword p_memsz;          /* Segment size in memory */
  Elf64_Xword p_align;          /* Segment alignment, file & memory */
} Elf64_Phdr;

typedef struct
{
    Elf64_Word	sh_name;	/* section name */
    Elf64_Word	sh_type;	/* SHT_... */
    Elf64_Xword	sh_flags;	/* SHF_... */
    Elf64_Addr	sh_addr;	/* virtual address */
    Elf64_Off	sh_offset;	/* file offset */
    Elf64_Xword	sh_size;	/* section size */
    Elf64_Word	sh_link;	/* misc info */
    Elf64_Word	sh_info;	/* misc info */
    Elf64_Xword	sh_addralign;	/* memory alignment */
    Elf64_Xword	sh_entsize;	/* entry size if table */
} Elf64_Shdr;

typedef struct {
	Elf64_Word	st_name;
	unsigned char	st_info;	/* bind, type: ELF_64_ST_... */
	unsigned char	st_other;
	Elf64_Half	st_shndx;	/* SHN_... */
	Elf64_Addr	st_value;
	Elf64_Xword	st_size;
} Elf64_Sym;

typedef struct
{
  Elf64_Addr    r_offset;               /* Address */
  Elf64_Xword   r_info;                 /* Relocation type and symbol index */
  Elf64_Sxword  r_addend;               /* Addend */
} Elf64_Rela;

typedef struct
{
  Elf64_Sxword  d_tag;                  /* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;                /* Integer value */
      Elf64_Addr d_ptr;                 /* Address value */
    } d_un;
} Elf64_Dyn;

typedef struct
{
  uint64_t a_type;              /* Entry type */
  union
    {
      uint64_t a_val;           /* Integer value */
      /* We use to have pointer elements added here.  We cannot do that,
         though, since it does not work when using 32-bit definitions
         on 64-bit platforms and vice versa.  */
    } a_un;
} Elf64_auxv_t;

#define AT_NULL         0               /* End of vector */
#define AT_IGNORE       1               /* Entry should be ignored */
#define AT_EXECFD       2               /* File descriptor of program */
#define AT_PHDR         3               /* Program headers for program */
#define AT_PHENT        4               /* Size of program header entry */
#define AT_PHNUM        5               /* Number of program headers */
#define AT_PAGESZ       6               /* System page size */
#define AT_BASE         7               /* Base address of interpreter */
#define AT_FLAGS        8               /* Flags */
#define AT_ENTRY        9               /* Entry point of program */
#define AT_NOTELF       10              /* Program is not ELF */
#define AT_UID          11              /* Real uid */
#define AT_EUID         12              /* Effective uid */
#define AT_GID          13              /* Real gid */
#define AT_EGID         14              /* Effective gid */
#define AT_CLKTCK       17              /* Frequency of times() */
#define AT_RANDOM       25              /* Address of 16 random bytes.  */

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define ELF_MIN_ALIGN   PAGE_SIZE
#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGESTART64(_v) ((_v) & ~(uint64_t)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

#define ELF_ALIGNDOWN(_v) ((_v) & ~(uint64_t)(ELF_MIN_ALIGN-1))
#define ELF_ALIGNUP(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

#endif
