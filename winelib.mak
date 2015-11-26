# CROSS_COMPILE ?=
CC = winegcc
RC = wrc

CFLAGS += -Wall -g -gdwarf-2 -fno-strict-aliasing -mno-cygwin
ifndef DEBUG
CFLAGS += -O2
endif
LDFLAGS += -g
# uncomment to use wine's msvcrt as the C library instead of glibc
# LDFLAGS += -mno-cygwin

ifdef ARM
CFLAGS += -mcpu=cortex-a8 -mtune=cortex-a8 -mfloat-abi=softfp -mfpu=neon
CFLAGS += -Wno-unused -fsigned-char
WGCC_FLAGS += -marm
ifneq ($(CROSS_COMPILE),)
WGCC_FLAGS += -b$(patsubst %-,%,$(CROSS_COMPILE))
endif
# wine defines wchar_t correctly, doesn't use -fshort-wchar, we can't too
WGCC_FLAGS += -fno-short-wchar
# WGCC_FLAGS += --sysroot $(WINEROOT)
CFLAGS += $(WGCC_FLAGS)
LDFLAGS += $(WGCC_FLAGS)

# should not be needed, but..
WINEROOT ?= $(HOME)/stuff/wine_arm/inst
CFLAGS += -isystem$(WINEROOT)/include/wine/msvcrt
CFLAGS += -isystem$(WINEROOT)/include/wine/windows
LDFLAGS += -L$(WINEROOT)/lib/wine -L$(WINEROOT)/lib

CVT_OPT = -a
BUILTIN = 1
export ARM
else
CFLAGS += -Wno-unused-but-set-variable
CFLAGS += -m32
LDFLAGS += -m32
endif


