#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "my_assert.h"
#include "my_str.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

static int find_protostr(char *dst, size_t dlen, FILE *fhdr,
	const char *sym, int *pline)
{
	int line = 0;
	char *p;

	rewind(fhdr);

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

// hmh..
static const char *known_types[] = {
	"char",
	"unsigned __int8",
	"int",
	"signed int",
	"unsigned int",
	"void",
	"BYTE",
	"WORD",
	"DWORD",
	"HMODULE",
	"HANDLE",
	"HWND",
	"LPCSTR",
	"size_t",
	"void *",
	"const void *",
	"FILE *",
};

static int check_type(const char *name)
{
	int i, l;

	for (i = 0; i < ARRAY_SIZE(known_types); i++) {
		l = strlen(known_types[i]);
		if (strncmp(known_types[i], name, l) == 0)
			return l;
	}

	return 0;
}

static const char *hdrfn;
static int pline = 0;

static int parse_protostr(char *protostr, char **reglist, int *cnt_out,
	int *is_stdcall)
{
	char regparm[16];
	char buf[256];
	int xarg = 0;
	int ret;
	char *p;

	p = protostr;
	if (p[0] == '/' && p[1] == '/') {
		//printf("warning: decl for sym '%s' is commented out\n", sym);
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

	p = next_word(buf, sizeof(buf), p);
	p = sskip(p);
	if (buf[0] == 0) {
		printf("%s:%d:%ld: cconv missing\n",
			hdrfn, pline, (p - protostr) + 1);
		return 1;
	}
	if      (strcmp(buf, "__cdecl") == 0)
		*is_stdcall = 0;
	else if (strcmp(buf, "__stdcall") == 0)
		*is_stdcall = 1;
	else if (strcmp(buf, "__userpurge") == 0)
		*is_stdcall = 1; // in all cases seen..
	else if (strcmp(buf, "__usercall") == 0)
		*is_stdcall = 0; // ..or is it?
	else {
		// TODO: __thiscall needs special handling (arg1~ecx)
		printf("%s:%d:%ld: unhandled cconv: '%s'\n",
			hdrfn, pline, (p - protostr) + 1, buf);
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
		if (strcmp(regparm, "eax") && strcmp(regparm, "ax")
		    && strcmp(regparm, "al"))
		{
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

	while (1) {
		p = sskip(p);
		if (*p == ')')
			break;
		if (*p == ',')
			p = sskip(p + 1);

		xarg++;

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
#if 0
		if (buf[0] == 0) {
			printf("%s:%d:%ld: idt missing for arg%d\n",
					hdrfn, pline, (p - protostr) + 1, xarg);
			return 1;
		}
#endif
		reglist[xarg - 1] = NULL;

		ret = get_regparm(regparm, sizeof(regparm), p);
		if (ret > 0) {
			p += ret;
			p = sskip(p);

			reglist[xarg - 1] = strdup(regparm);
		}
	}

	*cnt_out = xarg;

	return 0;
}

static int is_x86_reg_saved(const char *reg)
{
	static const char *nosave_regs[] = { "eax", "edx", "ecx" };
	int nosave = 0;
	int r;

	for (r = 0; r < ARRAY_SIZE(nosave_regs); r++)
		if (strcmp(reg, nosave_regs[r]) == 0)
			nosave = 1;

	return !nosave;
}

static void out_toasm_x86(FILE *f, char *sym, char *reg_list[], int reg_cnt,
	int is_stdcall)
{
	int have_normal = 0; // normal args
	int have_regs = 0;
	int must_save = 0;
	int sarg_ofs = 1; // stack offset to args, in DWORDs
	int args_repushed = 0;
	int i;

	for (i = 0; i < reg_cnt; i++) {
		if (reg_list[i] == NULL) {
			have_normal++;
			continue;
		}

		have_regs++;
		must_save |= is_x86_reg_saved(reg_list[i]);
	}

	fprintf(f, ".global _asm_%s\n", sym);
	fprintf(f, "_asm_%s:\n", sym);

	if (!have_regs && !is_stdcall) {
		fprintf(f, "\tjmp %s\n\n", sym);
		return;
	}

	if (!have_normal && !must_save && !is_stdcall) {
		// load arg regs
		for (i = 0; i < reg_cnt; i++) {
			fprintf(f, "\tmovl %d(%%esp), %%%s\n",
				(i + sarg_ofs) * 4, reg_list[i]);
		}
		fprintf(f, "\tjmp %s\n\n", sym);
		return;
	}

	// save the regs
	for (i = 0; i < reg_cnt; i++) {
		if (reg_list[i] != NULL && is_x86_reg_saved(reg_list[i])) {
			fprintf(f, "\tpushl %%%s\n", reg_list[i]);
			sarg_ofs++;
		}
	}

	// reconstruct arg stack
	for (i = reg_cnt - 1; i >= 0; i--) {
		if (reg_list[i] == NULL) {
			fprintf(f, "\tmovl %d(%%esp), %%eax\n",
				(i + sarg_ofs) * 4);
			fprintf(f, "\tpushl %%eax\n");
			sarg_ofs++;
			args_repushed++;
		}
	}
	my_assert(args_repushed, have_normal);

	// load arg regs
	for (i = 0; i < reg_cnt; i++) {
		if (reg_list[i] != NULL) {
			fprintf(f, "\tmovl %d(%%esp), %%%s\n",
				(i + sarg_ofs) * 4, reg_list[i]);
		}
	}

	fprintf(f, "\n\t# %s\n", is_stdcall ? "__stdcall" : "__cdecl");
	fprintf(f, "\tcall %s\n\n", sym);

	if (args_repushed && !is_stdcall)
		fprintf(f, "\tadd %d,%%esp\n", args_repushed * 4);

	// restore regs
	for (i = reg_cnt - 1; i >= 0; i--) {
		if (reg_list[i] != NULL && is_x86_reg_saved(reg_list[i]))
			fprintf(f, "\tpopl %%%s\n", reg_list[i]);
	}

	fprintf(f, "\tret\n\n");
}

static void out_fromasm_x86(FILE *f, char *sym, char *reg_list[], int reg_cnt,
	int is_stdcall)
{
	int have_normal = 0; // normal args
	int have_regs = 0;
	int sarg_ofs = 1; // stack offset to args, in DWORDs
	int stack_args;
	int i;

	for (i = 0; i < reg_cnt; i++) {
		if (reg_list[i] == NULL) {
			have_normal++;
			continue;
		}

		have_regs++;
	}

	fprintf(f, "# %s\n", is_stdcall ? "__stdcall" : "__cdecl");
	fprintf(f, ".global %s\n", sym);
	fprintf(f, "%s:\n", sym);

	if (!have_regs) {
		fprintf(f, "\tjmp _%s\n\n", sym);
		return;
	}

	fprintf(f, "\tpushl %%edx\n"); // just in case..
	sarg_ofs++;

	// construct arg stack
	stack_args = have_normal;
	for (i = reg_cnt - 1; i >= 0; i--) {
		if (reg_list[i] == NULL) {
			fprintf(f, "\tmovl %d(%%esp), %%edx\n",
				(sarg_ofs + stack_args - 1) * 4);
			fprintf(f, "\tpushl %%edx\n");
			stack_args--;
		}
		else {
			fprintf(f, "\tpushl %%%s\n", reg_list[i]);
		}
		sarg_ofs++;
	}

	// no worries about calling conventions - always __cdecl
	fprintf(f, "\n\tcall _%s\n\n", sym);

	if (sarg_ofs > 2)
		fprintf(f, "\tadd %d,%%esp\n", (sarg_ofs - 2) * 4);

	fprintf(f, "\tpopl %%edx\n");

	if (is_stdcall && have_normal)
		fprintf(f, "\tret $%d\n\n", have_normal * 4);
	else
		fprintf(f, "\tret\n\n");
}

int main(int argc, char *argv[])
{
	FILE *fout, *fsyms_to, *fsyms_from, *fhdr;
	char protostr[256];
	char line[256];
	char sym[256];
	char *reg_list[16];
	int is_stdcall = 0;
	int reg_cnt = 0;
	int ret;

	if (argc != 5) {
		printf("usage:\n%s <bridge.s> <toasm_symf> <fromasm_symf> <hdrf>\n",
			argv[0]);
		return 1;
	}

	hdrfn = argv[4];
	fhdr = fopen(hdrfn, "r");
	my_assert_not(fhdr, NULL);

	fsyms_from = fopen(argv[3], "r");
	my_assert_not(fsyms_from, NULL);

	fsyms_to = fopen(argv[2], "r");
	my_assert_not(fsyms_to, NULL);

	fout = fopen(argv[1], "w");
	my_assert_not(fout, NULL);

	fprintf(fout, ".text\n\n");
	fprintf(fout, "# to asm\n\n");

	while (fgets(line, sizeof(line), fsyms_to))
	{
		next_word(sym, sizeof(sym), line);
		if (sym[0] == 0 || sym[0] == ';' || sym[0] == '#')
			continue;

		ret = find_protostr(protostr, sizeof(protostr), fhdr,
			sym, &pline);
		if (ret != 0) {
			printf("%s: sym '%s' is missing\n",
				hdrfn, sym);
			goto out;
		}

		ret = parse_protostr(protostr, reg_list, &reg_cnt, &is_stdcall);
		if (ret)
			goto out;

		out_toasm_x86(fout, sym, reg_list, reg_cnt, is_stdcall);
	}

	fprintf(fout, "# from asm\n\n");

	while (fgets(line, sizeof(line), fsyms_from))
	{
		next_word(sym, sizeof(sym), line);
		if (sym[0] == 0 || sym[0] == ';' || sym[0] == '#')
			continue;

		ret = find_protostr(protostr, sizeof(protostr), fhdr,
			sym, &pline);
		if (ret != 0) {
			printf("%s: sym '%s' is missing\n",
				hdrfn, sym);
			goto out;
		}

		ret = parse_protostr(protostr, reg_list, &reg_cnt, &is_stdcall);
		if (ret)
			goto out;

		out_fromasm_x86(fout, sym, reg_list, reg_cnt, is_stdcall);
	}

	ret = 0;
out:
	fclose(fout);
	fclose(fsyms_to);
	fclose(fsyms_from);
	fclose(fhdr);
	if (ret)
		remove(argv[1]);

	return ret;
}
