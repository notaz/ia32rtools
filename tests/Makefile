
TESTS = reg_call1 reg_call2 reg_call3 reg_call4 reg_call5 reg_call6 \
	reg_call7 \
	reg_call_tail reg_call_tail2 reg_save reg_save2 \
	varargs ops x87 x87_f x87_s deref

all: $(addsuffix .ok,$(TESTS))

%.ok: %.expect.c %.out.c
	diff -u $^
	touch $@

%.out.h: %.asm %.seed.h ../stdc.list
	../tools/translate -hdr $@ $^

%.out.c: %.asm %.out.h ../stdc.list
	../tools/translate $@ $^

clean:
	$(RM) *.ok *.out.c *.out.h

.PHONY: all clean
.PRECIOUS: %.out.c
