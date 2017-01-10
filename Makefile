
TGT=line

#CXXFLAGS=
CXXFLAGS=-DDEBUG

SRCS=main.cpp line.cpp elfprocess.cpp syscall.cpp fsinstruction.cpp elfbinary.cpp elfexec.cpp elflibrary.cpp utils.cpp
OBJS=$(SRCS:.cpp=.o)

all: $(TGT)

$(TGT): $(OBJS)
	ld -arch x86_64 -macosx_version_min 10.12.0 $(OBJS) -o $(TGT) -lc -image_base 0xff000000 -pagezero_size 0x1000 -no_pie -framework CoreFoundation -lc++ 

clean:
	rm -rf $(OBJS) $(TGT)

.cpp.o:
	gcc -c -O0 $(CXXFLAGS) -g $<



