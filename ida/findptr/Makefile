CROSS_COMPILE = i586-mingw32msvc-
CC = $(CROSS_COMPILE)gcc
CXX = $(CROSS_COMPILE)g++
IDASDK = $(wildcard ../idasdk*)

CFLAGS += -Wall -Wno-sign-compare -fno-strict-aliasing
CFLAGS += -I$(IDASDK)/include/ -D__IDP__ -D__PLUGIN__ -D__NT__
LDLIBS += $(IDASDK)/lib/x86_win_gcc_32/ida.a
ifndef DEBUG
CFLAGS += -O2
endif

all: findptr.plw

%.plw: %.cpp
	$(CXX) -shared -o $@ $(CFLAGS) $^ $(LDFLAGS) $(LDLIBS)

clean:
	$(RM) findptr.plw
