CFLAGS += -Wall -ggdb
ifndef DEBUG
CFLAGS += -O2
endif

T = asmproc cmpmrg_text mkbridge translate

all: $(T)

clean:
	$(RM) $(T) *.o

translate: translate.o
mkbridge: mkbridge.o
mkbridge.o translate.o: protoparse.h my_assert.h my_str.h
