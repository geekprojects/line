Line - Line Is Not an Emulator
===

Line is an experiment to run Linux ELF binaries on Mac OS X without any
changes. It implements the bare minimum of Linux syscalls and the GNU
runtime dynamic linker.

It supports static binaries and dynamically linked binaries.

Requirements:
* [libdisasm (with 64 bit support!)](https://github.com/geekprojects/libdisasm)


Why?
---

Why not?

I started this just as an experiment to see if it was possible. There's a
potential use in running Docker containers pseudo-natively, but that
would be an awful lot of work. There are also a number of Linux binary-only
apps and tools out there (Such as Oracle) that would be great to run
without a virtual machine.


How?
---

There are a number of challenges to getting Linux ELF binaries to run:

* We have to Map the ELF binaries in to a Mac OS X process and handle
  dynamically loading any shared libraries ourselves.
* We need to intercept syscalls to the kernel. Linux obviously has a
  completely different API and we need to implement this. However, OS X
  doesn't natively allow you to trap syscalls.
* Linux uses the %fs register to store a pointer to the current thread's
  data. OS X doesn't use the %fs register and doesn't allow us to create
  a descriptor to point to our thread data. Once again, there's no easy
  way to intercept these instructions

To overcome these, Line:
* Implements its own ELF Dynamic Linker
* Patches the code dynamically by looking for syscalls and uses of the FS
  segment to replace them with breakpoints. Far jumps and calls are also
  patched so that they can be patched as necessary.
* Basic implementation of Linux syscalls either by calling the OSX
  equivalent, reimplementing it or just stubbing it. 

The libdisasm library is used to disassemble the code in order to patch it.
This wasn't 64 bit compatible, so I have updated it with (Very!) basic
64 bit support:

* [libdisasm](https://github.com/geekprojects/libdisasm)


Who?
---

Line was written by Ian Parker <ian@geekprojects.com> and is released under
the GPL v3 license.


To Do
---
* More syscalls!


Done!
---
* Instead of stepping through the code, see if we can find syscall and
  fs instructions ahead of time and insert breakpoint instructions.

