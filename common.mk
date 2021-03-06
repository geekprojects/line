
IMAGE_BASE=0x100000000

SUBDIR_TGT=subdir.o

OBJS=$(SRCS:.cpp=.o)
SUBDIROBJS=$(foreach dir,$(SUBDIRS), $(dir)/$(SUBDIR_TGT))
ALL_OBJS=$(OBJS) $(SUBDIROBJS)

CXXFLAGS=-O3
#CXXFLAGS=-DDEBUG -O2

subdirs:
	for dir in $(SUBDIRS) $(EXTRA_SUBDIRS) ; do \
	    $(MAKE) -C $$dir $(TARGET); res=$$?; \
	    if test $$res != 0 ; then exit $$res; fi; \
	done;

subdir.o: $(OBJS)
	ld -r $(OBJS) -o subdir.o

clean: TARGET=clean
clean: subdirs
	rm -rf $(OBJS) $(TGT)

.cpp.o:
	gcc -c -Wall -Werror -mdynamic-no-pic -I. -I$(TOP) -I/usr/local/include $(CXXFLAGS) -DIMAGE_BASE=$(IMAGE_BASE) $<



