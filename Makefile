
SRCS=main.cpp line.cpp elfprocess.cpp syscall.cpp fsinstruction.cpp elfbinary.cpp elfexec.cpp elflibrary.cpp utils.cpp
OBJS=$(SRCS:.cpp=.o)

#"/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ld" -demangle -dynamic -arch x86_64 -macosx_version_min 10.11.0 -syslibroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk -o line line.o -pagezero_size 1000 -lSystem /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/../lib/clang/7.3.0/lib/darwin/libclang_rt.osx.a

all: $(OBJS)
	ld -arch x86_64 -macosx_version_min 10.12.0 $(OBJS) -o line -lc -map map -image_base 0x7bf00000 -pagezero_size 0x1000 -no_pie -framework CoreFoundation -lc++ -sectcreate __TEXT __info_plist info.plist -demangle
	codesign -s codesign line

clean:
	rm -rf $(OBJS) line

#gcc -v $(OBJS) -Xlinker -pagezero_size -Xlinker 1000 -o line

.cpp.o:
	gcc -c -O0 -g $<



