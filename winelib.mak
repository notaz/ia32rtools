# CROSS_COMPILE ?=
CC = winegcc
RC = wrc

CFLAGS += -Wall -ggdb -fno-strict-aliasing -mno-cygwin
ifndef DEBUG
CFLAGS += -O2
endif
LDFLAGS += -ggdb

ifdef ARM
WGCC_FLAGS += -marm -b$(patsubst %-,%,$(CROSS_COMPILE))
# WGCC_FLAGS += --sysroot $(HOME)/stuff/wine_arm/wine-arm-build/
CFLAGS += $(WGCC_FLAGS)
CFLAGS += -mcpu=cortex-a8 -mtune=cortex-a8 -mfloat-abi=softfp -mfpu=neon
CFLAGS += -Wno-unused
LDFLAGS += $(WGCC_FLAGS)
# should not be needed, but..
CFLAGS += -isystem$(HOME)/stuff/wine_arm/inst/include/wine/msvcrt
CFLAGS += -isystem$(HOME)/stuff/wine_arm/inst/include/wine/windows
LDFLAGS += -L$(HOME)/stuff/wine_arm/inst/lib/wine
CVT_OPT = -a
BUILTIN = 1
else
CFLAGS += -Wno-unused-but-set-variable
CFLAGS += -m32
LDFLAGS += -m32
endif


