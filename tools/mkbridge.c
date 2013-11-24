#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "my_assert.h"
#include "my_str.h"

static int find_protostr(char *dst, size_t dlen, FILE *fhdr,
	const char *sym, int *pline)
{
	int line = 0;
	char *p;

	while (fgets(dst, dlen, fhdr))
	{
		line++;
		if (strstr(dst, sym) != NULL)
			break;
	}
	*pline = line;

	if (feof(fhdr))
		return -1;

	p = dst + strlen(dst);
	for (p--; p > dst && my_isblank(*p); --p)
		*p = 0;

	return 0;
}

static int get_regparm(char *dst, size_t dlen, char *p)
{
	int i, o;

	if (*p != '<')
		return 0;

	for (o = 0, i = 1; o < dlen; i++) {
		if (p[i] == 0)
			return 0;
		if (p[i] == '>')
			break;
		dst[o++] = p[i];
	}
	dst[o] = 0;
	return i + 1;
}

static const char *known_types[] = {
	"unsigned int",
	"signed int",
	"int",
	"void",
	"DWORD",
	"HMODULE",
	"HANDLE",
	"HWND",
};

static int check_type(const char *name)
{
	int i, l;

	for (i = 0; i < sizeof(known_types) / sizeof(known_types[0]); i++) {
		l = strlen(known_types[i]);
		if (strncmp(known_types[i], name, l) == 0)
			return l;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	FILE *fout, *fsyms, *fhdr;
	const char *hdrfn;
	char protostr[256];
	char line[256];
	char sym[256];
	char buf[256];
	char regparm[16];
	char *p;
	int first_regparm = 0;
	int have_regparm;
	int pline = 0;
	int xarg;
	int ret;

	if (argc != 4) {
		// -c - patch callsites
		printf("usage:\n%s <bridge.s> <symf> <hdrf>\n",
			argv[0]);
		return 1;
	}

	hdrfn = argv[3];
	fhdr = fopen(hdrfn, "r");
	my_assert_not(fhdr, NULL);

	fsyms = fopen(argv[2], "r");
	my_assert_not(fsyms, NULL);

	fout = fopen(argv[1], "w");
	my_assert_not(fout, NULL);

	fprintf(fout, ".text\n\n");

	while (fgets(line, sizeof(line), fsyms))
	{
		next_word(sym, sizeof(sym), line);
		if (sym[0] == 0 || sym[0] == ';' || sym[0] == '#')
			continue;

		ret = find_protostr(protostr, sizeof(protostr), fhdr,
			sym, &pline);
		if (ret != 0) {
			printf("%s: sym '%s' is missing\n",
				hdrfn, sym);
			return 1;
		}

		p = protostr;
		if (p[0] == '/' && p[1] == '/') {
			printf("warning: decl for sym '%s' is commented out\n", sym);
			p = sskip(p + 2);
		}

		ret = check_type(p);
		if (ret <= 0) {
			printf("%s:%d:%ld: unhandled return in '%s'\n",
				hdrfn, pline, (p - protostr) + 1, protostr);
			return 1;
		}
		p += ret;
		p = sskip(p);

		// ignore calling convention specifier, for now
		p = next_word(buf, sizeof(buf), p);
		p = sskip(p);
		if (buf[0] == 0) {
			printf("%s:%d:%ld: cconv missing\n",
				hdrfn, pline, (p - protostr) + 1);
			return 1;
		}

		p = next_idt(buf, sizeof(buf), p);
		p = sskip(p);
		if (buf[0] == 0) {
			printf("%s:%d:%ld: func name missing\n",
				hdrfn, pline, (p - protostr) + 1);
			return 1;
		}

		ret = get_regparm(regparm, sizeof(regparm), p);
		if (ret > 0) {
			if (strcmp(regparm, "eax") && strcmp(regparm, "ax")) {
				printf("%s:%d:%ld: bad regparm: %s\n",
					hdrfn, pline, (p - protostr) + 1, regparm);
				return 1;
			}
			p += ret;
			p = sskip(p);
		}

		if (*p != '(') {
			printf("%s:%d:%ld: '(' expected, got '%c'\n",
				hdrfn, pline, (p - protostr) + 1, *p);
			return 1;
		}
		p++;

		fprintf(fout, ".global _asm_%s\n", sym);
		fprintf(fout, "_asm_%s:\n", sym);

		xarg = 1;
		while (1) {
			p = sskip(p);
			if (*p == ')')
				break;
			if (*p == ',')
				p = sskip(p + 1);

			ret = check_type(p);
			if (ret <= 0) {
				printf("%s:%d:%ld: unhandled type for arg%d\n",
					hdrfn, pline, (p - protostr) + 1, xarg);
				return 1;
			}
			p += ret;
			p = sskip(p);

			p = next_idt(buf, sizeof(buf), p);
			p = sskip(p);
			if (buf[0] == 0) {
				printf("%s:%d:%ld: idt missing for arg%d\n",
					hdrfn, pline, (p - protostr) + 1, xarg);
				return 1;
			}

			have_regparm = 0;
			ret = get_regparm(regparm, sizeof(regparm), p);
			if (ret > 0) {
				p += ret;
				p = sskip(p);

				have_regparm = 1;
				fprintf(fout, "\t movl %d(%%esp), %%%s\n",
					xarg * 4, regparm);
			}
			if (xarg == 1)
				first_regparm = have_regparm;
			else if (have_regparm != first_regparm) {
				printf("%s:%d:%ld: mixed regparm is unhandled\n",
					hdrfn, pline, (p - protostr) + 1);
				return 1;
			}
		}

		fprintf(fout, "\t jmp %s\n\n", sym);
	}

	fclose(fout);
	return 0;
}
