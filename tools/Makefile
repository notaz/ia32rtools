CFLAGS += -Wall -ggdb
ifndef DEBUG
CFLAGS += -O2
endif

T = asmproc cmpmrg_text mkbridge translate

all: $(T)

clean:
	$(RM) $(T)
