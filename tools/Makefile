CFLAGS += -Wall -ggdb
ifndef DEBUG
CFLAGS += -O2
endif

T = asmproc cmpmrg_text mkbridge translate cvt_data

all: $(T)

clean:
	$(RM) $(T) *.o

translate: translate.o
mkbridge: mkbridge.o
cvt_data: cvt_data.o
mkbridge.o translate.o cvt_data.o: protoparse.h my_assert.h my_str.h
