#ifndef __LINE_RTLD_H_
#define __LINE_RTLD_H_

#include <sys/stat.h>

typedef long int Lmid_t;
typedef unsigned long long int hp_timing_t;

struct r_file_id
{
    dev_t dev;
    ino64_t ino;
};

#define __SIZEOF_PTHREAD_MUTEX_T 40
struct linux_pthread_mutex_t
{
    char __fill[__SIZEOF_PTHREAD_MUTEX_T];
};

#define DL_NNS 16

    struct auditstate
    {
      uintptr_t cookie;
      unsigned int bindflags;
    };

struct link_map;

struct r_scope_elem
{
    /* Array of maps for the scope.  */
    struct link_map **r_list;
    /* Number of entries in the scope.  */
    unsigned int r_nlist;
};

struct r_search_path_elem;

struct r_search_path_struct
{
    struct r_search_path_elem **dirs;
    int malloced;
};

struct link_map_machine
{
    Elf64_Addr plt; /* Address of .plt + 0x16 */
    Elf64_Addr gotplt; /* Address of .got + 0x18 */
    void *tlsdesc_table; /* Address of TLS descriptor hash table.  */
};


#define  	DT_NUM 		34
#define DT_THISPROCNUM    0
#define DT_VERSIONTAGNUM 16
#define DT_EXTRANUM    3
#define DT_VALNUM 12
#define DT_ADDRNUM 11

struct link_map
{
    Elf64_Addr l_addr;          /* Difference between the address in the ELF
                                   file and the addresses in memory.  */
    char *l_name;               /* Absolute file name object was found in.  */
    Elf64_Dyn* l_ld;            /* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
    /* This is an element which is only ever different from a pointer to
       the very same copy of this type for ld.so when it is used in more
       than one namespace.  */
    struct link_map *l_real;
    Lmid_t l_ns;
    struct libname_list *l_libname;
    Elf64_Dyn *l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
                      + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
    const Elf64_Phdr *l_phdr;   /* Pointer to program header table in core.  */
    Elf64_Addr l_entry;         /* Entry point location.  */
    Elf64_Half l_phnum;         /* Number of program header entries.  */
    Elf64_Half l_ldnum;         /* Number of dynamic segment entries.  */
    struct r_scope_elem l_searchlist;

    /* We need a special searchlist to process objects marked with
       DT_SYMBOLIC.  */
    struct r_scope_elem l_symbolic_searchlist;

    /* Dependent object that first caused this object to be loaded.  */
    struct link_map *l_loader;

    /* Array with version names.  */
    struct r_found_version *l_versions;
    unsigned int l_nversions;

    /* Symbol hash table.  */
    Elf_Symndx l_nbuckets;
    Elf64_Word l_gnu_bitmask_idxbits;
    Elf64_Word l_gnu_shift;
    const Elf64_Addr *l_gnu_bitmask;
    union
    {
      const Elf64_Word *l_gnu_buckets;
      const Elf_Symndx *l_chain;
    };
    union
    {
      const Elf64_Word *l_gnu_chain_zero;
      const Elf_Symndx *l_buckets;
    };
    unsigned int l_direct_opencount; /* Reference count for dlopen/dlclose.  */
    enum                        /* Where this object came from.  */
      {
        lt_executable,          /* The main executable program.  */
        lt_library,             /* Library needed by main executable.  */
        lt_loaded               /* Extra run-time loaded shared object.  */
      } l_type:2;
    unsigned int l_relocated:1; /* Nonzero if object's relocations done.  */
    unsigned int l_init_called:1; /* Nonzero if DT_INIT function called.  */
    unsigned int l_global:1;    /* Nonzero if object in _dl_global_scope.  */
    unsigned int l_reserved:2;  /* Reserved for internal use.  */
    unsigned int l_phdr_allocated:1; /* Nonzero if the data structure pointed
                                        to by `l_phdr' is allocated.  */
    unsigned int l_soname_added:1; /* Nonzero if the SONAME is for sure in
                                      the l_libname list.  */
    unsigned int l_faked:1;     /* Nonzero if this is a faked descriptor
                                   without associated file.  */
    unsigned int l_need_tls_init:1; /* Nonzero if GL(dl_init_static_tls)
                                       should be called on this link map
                                       when relocation finishes.  */
    unsigned int l_auditing:1;  /* Nonzero if the DSO is used in auditing.  */
    unsigned int l_audit_any_plt:1; /* Nonzero if at least one audit module
                                       is interested in the PLT interception.*/
    unsigned int l_removed:1;   /* Nozero if the object cannot be used anymore
                                   since it is removed.  */
    unsigned int l_contiguous:1; /* Nonzero if inter-segment holes are
                                    mprotected or if no holes are present at
                                    all.  */
    unsigned int l_symbolic_in_local_scope:1; /* Nonzero if l_local_scope
                                                 during LD_TRACE_PRELINKING=1
                                                 contains any DT_SYMBOLIC
                                                 libraries.  */
    unsigned int l_free_initfini:1; /* Nonzero if l_initfini can be
                                       freed, ie. not allocated with
                                       the dummy malloc in ld.so.  */

    /* Collected information about own RPATH directories.  */
    struct r_search_path_struct l_rpath_dirs;

    /* Collected results of relocation while profiling.  */
    struct reloc_result
    {
      Elf64_Addr addr;
      struct link_map *bound;
      unsigned int boundndx;
      uint32_t enterexit;
      unsigned int flags;
    } *l_reloc_result;

    /* Pointer to the version information if available.  */
    Elf64_Versym *l_versyms;

    /* String specifying the path where this object was found.  */
    const char *l_origin;

    /* Start and finish of memory map for this object.  l_map_start
       need not be the same as l_addr.  */
    Elf64_Addr l_map_start, l_map_end;
    /* End of the executable part of the mapping.  */
    Elf64_Addr l_text_end;

    /* Default array for 'l_scope'.  */
    struct r_scope_elem *l_scope_mem[4];
    /* Size of array allocated for 'l_scope'.  */
    size_t l_scope_max;
    /* This is an array defining the lookup scope for this link map.
       There are initially at most three different scope lists.  */
    struct r_scope_elem **l_scope;

    /* A similar array, this time only with the local scope.  This is
       used occasionally.  */
    struct r_scope_elem *l_local_scope[2];

    /* This information is kept to check for sure whether a shared
       object is the same as one already loaded.  */
    struct r_file_id l_file_id;

    /* Collected information about own RUNPATH directories.  */
    struct r_search_path_struct l_runpath_dirs;

    /* List of object in order of the init and fini calls.  */
    struct link_map **l_initfini;

    /* List of the dependencies introduced through symbol binding.  */
    struct link_map_reldeps
      {
        unsigned int act;
        struct link_map *list[];
      } *l_reldeps;
    unsigned int l_reldepsmax;

    /* Nonzero if the DSO is used.  */
    unsigned int l_used;

    /* Various flag words.  */
    Elf64_Word l_feature_1;
    Elf64_Word l_flags_1;
    Elf64_Word l_flags;

    /* Temporarily used in `dl_close'.  */
    int l_idx;

    struct link_map_machine l_mach;

    struct
    {
      const Elf64_Sym *sym;
      int type_class;
      struct link_map *value;
      const Elf64_Sym *ret;
    } l_lookup_cache;

    /* Thread-local storage related info.  */

    /* Start of the initialization image.  */
    void *l_tls_initimage;
    /* Size of the initialization image.  */
    size_t l_tls_initimage_size;
    /* Size of the TLS block.  */
    size_t l_tls_blocksize;
    /* Alignment requirement of the TLS block.  */
    size_t l_tls_align;
    /* Offset of first byte module alignment.  */
    size_t l_tls_firstbyte_offset;
    /* For objects present at startup time: offset in the static TLS block.  */
    ptrdiff_t l_tls_offset;
    /* Index of the module in the dtv array.  */
    size_t l_tls_modid;

    /* Number of thread_local objects constructed by this DSO.  This is
       atomically accessed and modified and is not always protected by the load
       lock.  See also: CONCURRENCY NOTES in cxa_thread_atexit_impl.c.  */
    size_t l_tls_dtor_count;

    /* Information used to change permission after the relocations are
       done.  */
    Elf64_Addr l_relro_addr;
    size_t l_relro_size;

    unsigned long long int l_serial;

    /* Audit information.  This array apparent must be the last in the
       structure.  Never add something after it.  */
    struct auditstate l_audit[0];
};
struct r_debug
  {
    int r_version;              /* Version number for this protocol.  */

    struct link_map *r_map;     /* Head of the chain of loaded objects.  */

    /* This is the address of a function internal to the run-time linker,
       that will always be called when the linker begins to map in a
       library or unmap it, and again when the mapping change is complete.
       The debugger can set a breakpoint at this address if it wants to
       notice shared object mapping changes.  */
    Elf64_Addr r_brk;
    enum
      {
        /* This state value describes the mapping change taking place when
           the `r_brk' address is called.  */
        RT_CONSISTENT,          /* Mapping change is complete.  */
        RT_ADD,                 /* Beginning to add a new object.  */
        RT_DELETE               /* Beginning to remove an object mapping.  */
      } r_state;

    Elf64_Addr r_ldbase;        /* Base address the linker is loaded at.  */
  };

struct link_namespaces
  {
    /* A pointer to the map for the main map.  */
    struct link_map *_ns_loaded;
    /* Number of object in the _dl_loaded list.  */
    unsigned int _ns_nloaded;
    /* Direct pointer to the searchlist of the main object.  */
    struct r_scope_elem *_ns_main_searchlist;
    /* This is zero at program start to signal that the global scope map is
       allocated by rtld.  Later it keeps the size of the map.  It might be
       reset if in _dl_close if the last global object is removed.  */
    size_t _ns_global_scope_alloc;
    /* Search table for unique objects.  */
    struct unique_sym_table
    {
      linux_pthread_mutex_t lock;
      struct unique_sym
      {
        uint32_t hashval;
        const char *name;
        const Elf64_Sym *sym;
        const struct link_map *map;
      } *entries;
      size_t size;
      size_t n_elements;
      void (*free) (void *);
    } _ns_unique_sym_table;
    /* Keep track of changes to each namespace' list.  */
    struct r_debug _ns_debug;
};

struct rtld_global
{
    link_namespaces _dl_ns[DL_NNS];
    size_t _dl_nns;

  /* During the program run we must not modify the global data of
     loaded shared object simultanously in two threads.  Therefore we
     protect `_dl_open' and `_dl_close' in dl-close.c.

     This must be a recursive lock since the initializer function of
     the loaded object might as well require a call to this function.
     At this time it is not anymore a problem to modify the tables.  */
  linux_pthread_mutex_t _dl_load_lock;
  /* This lock is used to keep __dl_iterate_phdr from inspecting the
     list of loaded objects while an object is added to or removed
     from that list.  */
  linux_pthread_mutex_t _dl_load_write_lock;

  /* Incremented whenever something may have been added to dl_loaded.  */
  unsigned long long _dl_load_adds;

  /* The object to be initialized first.  */
  struct link_map *_dl_initfirst;

  /* Start time on CPU clock.  */
  hp_timing_t _dl_cpuclock_offset;

  /* Map of shared object to be profiled.  */
  struct link_map *_dl_profile_map;

  /* Counters for the number of relocations performed.  */
  unsigned long int _dl_num_relocations;
  unsigned long int _dl_num_cache_relocations;

  /* List of search directories.  */
  struct r_search_path_elem *_dl_all_dirs;

// MAYBE?
  void **(*_dl_error_catch_tsd) (void) __attribute__ ((const));

  /* Structure describing the dynamic linker itself.  We need to
     reserve memory for the data the audit libraries need.  */
  struct link_map _dl_rtld_map;

  struct auditstate audit_data[DL_NNS];

  void (*_dl_rtld_lock_recursive) (void *);
  void (*_dl_rtld_unlock_recursive) (void *);

    /* If loading a shared object requires that we make the stack executable
       when it was not, we do it by calling this function.
       It returns an errno code or zero on success.  */
    int (*_dl_make_stack_executable_hook) (void **);

    /* Prevailing state of the stack, PF_X indicating it's executable.  */
    Elf64_Word _dl_stack_flags;

    /* Flag signalling whether there are gaps in the module ID allocation.  */
    bool _dl_tls_dtv_gaps;
    /* Highest dtv index currently needed.  */
    size_t _dl_tls_max_dtv_idx;
};

struct rtld_global_ro
{
    int _dl_debug_mask;
    unsigned int _dl_osversion;
    const char *_dl_platform;
    size_t _dl_platformlen;
    size_t _dl_pagesize;
    int _dl_inhibit_cache;
    struct r_scope_elem _dl_initial_searchlist;
    int _dl_clktck;
    int _dl_verbose;
    int _dl_debug_fd;
    int _dl_lazy;
    int _dl_bind_not;
    int _dl_dynamic_weak;
    unsigned int _dl_fpu_control;
    int _dl_correct_cache_id;
    uint64_t _dl_hwcap;
    uint64_t _dl_hwcap_mask;
};

#endif
