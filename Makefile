
TGT=line

IMAGE_BASE=0xff000000

CXXFLAGS=-O3
#CXXFLAGS=-DDEBUG -O2

SRCS=main.cpp line.cpp elfprocess.cpp syscall.cpp fsinstruction.cpp elfbinary.cpp elfexec.cpp elflibrary.cpp utils.cpp filesystem.cpp
OBJS=$(SRCS:.cpp=.o)

all: $(TGT)

$(TGT): $(OBJS)
	ld -arch x86_64 -macosx_version_min 10.12.0 $(OBJS) -o $(TGT) -lc -image_base $(IMAGE_BASE) -pagezero_size 0x1000 -no_pie -framework CoreFoundation -lc++ 

clean:
	rm -rf $(OBJS) $(TGT)

.cpp.o:
	gcc -c -Wall -Werror $(CXXFLAGS) -DIMAGE_BASE=$(IMAGE_BASE) $<



