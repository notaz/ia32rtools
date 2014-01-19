#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "my_assert.h"
#include "my_str.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define IS(w, y) !strcmp(w, y)

#include "protoparse.h"

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

static void out_toasm_x86(FILE *f, const char *sym_in,
	const char *sym_out, const struct parsed_proto *pp)
{
	int must_save = 0;
	int sarg_ofs = 1; // stack offset to args, in DWORDs
	int args_repushed = 0;
	int argc_repush;
	int i;

	argc_repush = pp->argc;
	if (pp->is_vararg)
		argc_repush = ARRAY_SIZE(pp->arg); // hopefully enough?

	for (i = 0; i < pp->argc; i++) {
		if (pp->arg[i].reg != NULL)
			must_save |= is_x86_reg_saved(pp->arg[i].reg);
	}

	fprintf(f, ".global %s%s\n", pp->is_fastcall ? "@" : "_", sym_in);
	fprintf(f, "%s%s:\n", pp->is_fastcall ? "@" : "_", sym_in);

	if (pp->argc_reg == 0 || pp->is_fastcall) {
		fprintf(f, "\t# %s\n",
		  pp->is_fastcall ? "__fastcall" :
		  (pp->is_stdcall ? "__stdcall" : "__cdecl"));
		fprintf(f, "\tjmp %s\n\n", sym_out);
		return;
	}

	if (pp->argc_stack == 0 && !must_save && !pp->is_stdcall
	     && !pp->is_vararg)
	{
		// load arg regs
		for (i = 0; i < pp->argc; i++) {
			fprintf(f, "\tmovl %d(%%esp), %%%s\n",
				(i + sarg_ofs) * 4, pp->arg[i].reg);
		}
		fprintf(f, "\tjmp %s\n\n", sym_out);
		return;
	}

	// save the regs
	for (i = 0; i < pp->argc; i++) {
		if (pp->arg[i].reg != NULL && is_x86_reg_saved(pp->arg[i].reg)) {
			fprintf(f, "\tpushl %%%s\n", pp->arg[i].reg);
			sarg_ofs++;
		}
	}

	// reconstruct arg stack
	for (i = argc_repush - 1; i >= 0; i--) {
		if (pp->arg[i].reg == NULL) {
			fprintf(f, "\tmovl %d(%%esp), %%eax\n",
				(i + sarg_ofs) * 4);
			fprintf(f, "\tpushl %%eax\n");
			sarg_ofs++;
			args_repushed++;
		}
	}
	// my_assert(args_repushed, pp->argc_stack);

	// load arg regs
	for (i = 0; i < pp->argc; i++) {
		if (pp->arg[i].reg != NULL) {
			fprintf(f, "\tmovl %d(%%esp), %%%s\n",
				(i + sarg_ofs) * 4, pp->arg[i].reg);
		}
	}

	fprintf(f, "\n\t# %s\n", pp->is_stdcall ? "__stdcall" : "__cdecl");
	fprintf(f, "\tcall %s\n\n", sym_out);

	if (args_repushed && !pp->is_stdcall)
		fprintf(f, "\tadd $%d,%%esp\n", args_repushed * 4);

	// restore regs
	for (i = pp->argc - 1; i >= 0; i--) {
		if (pp->arg[i].reg != NULL && is_x86_reg_saved(pp->arg[i].reg))
			fprintf(f, "\tpopl %%%s\n", pp->arg[i].reg);
	}

	fprintf(f, "\tret\n\n");
}

static void out_fromasm_x86(FILE *f, const char *sym,
	const struct parsed_proto *pp)
{
	int sarg_ofs = 1; // stack offset to args, in DWORDs
	int saved_regs = 0;
	int argc_repush;
	int stack_args;
	int ret64;
	int i;

	argc_repush = pp->argc;
	stack_args = pp->argc_stack;
	if (pp->is_vararg) {
		argc_repush = ARRAY_SIZE(pp->arg); // hopefully enough?
		stack_args = argc_repush - pp->argc_reg;
	}

	ret64 = strstr(pp->ret_type.name, "int64") != NULL;

	fprintf(f, "# %s",
	  pp->is_fastcall ? "__fastcall" :
	  (pp->is_stdcall ? "__stdcall" : "__cdecl"));
	if (ret64)
		 fprintf(f, " ret64");
	fprintf(f, "\n.global %s\n", sym);
	fprintf(f, "%s:\n", sym);

	if (pp->argc_reg == 0 || pp->is_fastcall) {
		fprintf(f, "\tjmp %s%s",
			pp->is_fastcall ? "@" : "_", sym);
		if (pp->is_stdcall && pp->argc > 0)
			fprintf(f, "@%d", pp->argc * 4);
		fprintf(f, "\n\n");
		return;
	}

	// at least sc sub_47B150 needs edx to be preserved
	// int64 returns use edx:eax - no edx save
	// we use ecx also as scratch
	fprintf(f, "\tpushl %%ecx\n");
	saved_regs++;
	sarg_ofs++;
	if (!ret64) {
		fprintf(f, "\tpushl %%edx\n");
		saved_regs++;
		sarg_ofs++;
	}

	// construct arg stack
	for (i = argc_repush - 1; i >= 0; i--) {
		if (pp->arg[i].reg == NULL) {
			fprintf(f, "\tmovl %d(%%esp), %%ecx\n",
				(sarg_ofs + stack_args - 1) * 4);
			fprintf(f, "\tpushl %%ecx\n");
			stack_args--;
		}
		else {
			if (IS(pp->arg[i].reg, "ecx"))
				// must reload original ecx
				fprintf(f, "\tmovl %d(%%esp), %%ecx\n",
					(sarg_ofs - 2) * 4);

			fprintf(f, "\tpushl %%%s\n", pp->arg[i].reg);
		}
		sarg_ofs++;
	}

	// no worries about calling conventions - always __cdecl
	fprintf(f, "\n\tcall _%s\n\n", sym);

	if (sarg_ofs > saved_regs + 1)
		fprintf(f, "\tadd $%d,%%esp\n",
			(sarg_ofs - (saved_regs + 1)) * 4);

	if (!ret64)
		fprintf(f, "\tpopl %%edx\n");
	fprintf(f, "\tpopl %%ecx\n");

	if (pp->is_stdcall && pp->argc_stack)
		fprintf(f, "\tret $%d\n\n", pp->argc_stack * 4);
	else
		fprintf(f, "\tret\n\n");
}

int main(int argc, char *argv[])
{
	FILE *fout, *fsyms_to, *fsyms_from, *fhdr;
	const struct parsed_proto *pp;
	char line[256];
	char sym_noat[256];
	char sym[256];
	char *p;
	int ret = 1;

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

		// IDA asm doesn't do '@' notation..
		strcpy(sym_noat, sym);
		p = strchr(sym_noat, '@');
		if (p != NULL)
			*p = 0;

		pp = proto_parse(fhdr, sym_noat, 0);
		if (pp == NULL)
			goto out;

		out_toasm_x86(fout, sym, sym_noat, pp);
	}

	fprintf(fout, "# from asm\n\n");

	while (fgets(line, sizeof(line), fsyms_from))
	{
		next_word(sym, sizeof(sym), line);
		if (sym[0] == 0 || sym[0] == ';' || sym[0] == '#')
			continue;

		pp = proto_parse(fhdr, sym, 0);
		if (pp == NULL)
			goto out;

		out_fromasm_x86(fout, sym, pp);
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
