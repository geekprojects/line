Line - Line Is Not an Emulator
===

Line is an experiment to run Linux ELF binaries on Mac OS X without any
changes. It implements the bare minimum of Linux syscalls and the GNU
runtime dynamic linker.

It currently supports static binaries and very simple dynamically linked
binaries.


Why?
---

Why not?

I started this just as an experiment to see if it was possible. I guess
there's a potential use in running Docker containers pseudo-natively, but that
would be an awful lot of work.


How?
---

There are a number of challenges to getting Linux ELF binaries to run:

* We have to Map the ELF binaries in to a Mac OS X process and handle
  dynamically loading any shared libraries ourselves.
* We need to intercept syscalls to the kernel. Linux obviously has a
  completely different API and we need to implement this. However, OS X
  doesn't natively allow you to trap syscalls. The ptrace implementation
  lacks a PT_SYSCALL or similar. The only way to intercept syscalls is
  to step through the code (By setting the T flag in eflags), find syscall
  instructions and handle them.
* Linux uses the %fs register to store a pointer to the current thread's
  data. OS X doesn't use the %fs register and doesn't allow us to create
  a descriptor to point to our thread data. Once again, the only way to
  handle access to the thread data is to intercept instructions that use
  the %fs register and implement them.


Who?
---

Line was written by Ian Parker <ian@geekprojects.com> and is released under
the GPL v3 license.


To Do
---
* More syscalls!
* Instead of stepping through the code, see if we can find syscall and
  fs instructions ahead of time and insert breakpoint instructions.


