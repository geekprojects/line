
TGT=line
IDENTITY=codesign

SRCS=main.cpp line.cpp elfprocess.cpp syscall.cpp fsinstruction.cpp elfbinary.cpp elfexec.cpp elflibrary.cpp utils.cpp
OBJS=$(SRCS:.cpp=.o)

all: $(TGT)

$(TGT): $(OBJS)
	ld -arch x86_64 -macosx_version_min 10.12.0 $(OBJS) -o $(TGT) -lc -map map -image_base 0x7bf00000 -pagezero_size 0x1000 -no_pie -framework CoreFoundation -lc++ -sectcreate __TEXT __info_plist info.plist -demangle
	codesign -s $(IDENTITY) $(TGT)

clean:
	rm -rf $(OBJS) $(TGT)

.cpp.o:
	gcc -c -O0 -g $<



