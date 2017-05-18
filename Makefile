TOP=.
TGT=line

SUBDIRS=syscalls
SRCS=main.cpp line.cpp process.cpp fsinstruction.cpp elfbinary.cpp elfexec.cpp elflibrary.cpp utils.cpp filesystem.cpp kernel.cpp thread.cpp mainthread.cpp glibcruntime.cpp logger.cpp patcher.cpp
#OBJS=$(SRCS:.cpp=.o)

all: TARGET=all
all: $(TGT)

include common.mk

$(TGT): $(OBJS) subdirs
	ld -arch x86_64 -macosx_version_min 10.12.0 $(ALL_OBJS) -o $(TGT) -lc -image_base $(IMAGE_BASE) -pagezero_size 0x1000 -no_pie -framework CoreFoundation -lc++ -segaddr LINE_EXEC 0x1000 -ldisasm


