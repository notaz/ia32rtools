/*
 * ia32rtools
 * (C) notaz, 2013,2014
 *
 * This work is licensed under the terms of 3-clause BSD license.
 * See COPYING file in the top-level directory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "my_assert.h"
#include "my_str.h"
#include "common.h"

#include "protoparse.h"

static const char *c_save_regs[] = { "ebx", "esi", "edi", "ebp" };

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

// output decorated name
static const char *pp_to_name(const struct parsed_proto *pp)
{
	static char buf[256];
	char atval[16];

	if (!pp->is_fastcall && pp->argc_reg != 0) {
		// can only be handled by __cdecl C func
		snprintf(buf, sizeof(buf), "_%s", pp->name);
		return buf;
	}

	atval[0] = 0;
	if (pp->is_stdcall) {
		snprintf(atval, sizeof(atval), "@%d",
			pp->argc * 4);
	}
	snprintf(buf, sizeof(buf), "%s%s%s",
		pp->is_fastcall ? "@" : "_",
		pp->name, atval);

	return buf;
}

static void out_toasm_x86(FILE *f, const char *sym_out,
	const struct parsed_proto *pp)
{
	int must_save = 0;
	int sarg_ofs = 1; // stack offset to args, in DWORDs
	int args_repushed = 0;
	int argc_repush;
	const char *name;
	int i;

	argc_repush = pp->argc;
	if (pp->is_vararg)
		argc_repush = ARRAY_SIZE(pp->arg); // hopefully enough?

	for (i = 0; i < pp->argc; i++) {
		if (pp->arg[i].reg != NULL)
			must_save |= is_x86_reg_saved(pp->arg[i].reg);
	}

	name = pp_to_name(pp);
	fprintf(f, ".global %s\n", name);
	fprintf(f, "%s:\n", name);

	if (pp->argc_reg == 0 || pp->is_fastcall) {
		fprintf(f, "\t# %s\n",
		  pp->is_fastcall ? "__fastcall" :
		  (pp->is_stdcall ? "__stdcall" : "__cdecl"));
		fprintf(f, "\tjmp %s\n\n", sym_out);
		return;
	}

	if (pp->argc_stack == 0 && !must_save && !pp->is_stdcall
	     && !pp->is_vararg && !pp->has_retreg)
	{
		// load arg regs
		for (i = 0; i < pp->argc; i++) {
			fprintf(f, "\tmovl %d(%%esp), %%%s\n",
				(i + sarg_ofs) * 4, pp->arg[i].reg);
		}
		fprintf(f, "\tjmp %s\n\n", sym_out);
		return;
	}

	// asm_stack_args | saved_regs | ra | args_from_c

	// save the regs
	// because we don't always know what we are calling,
	// be safe and save everything that has to be saved in __cdecl
	for (i = 0; i < ARRAY_SIZE(c_save_regs); i++) {
		fprintf(f, "\tpushl %%%s\n", c_save_regs[i]);
		sarg_ofs++;
	}

	// reconstruct arg stack for asm
	for (i = argc_repush - 1; i >= 0; i--) {
		if (pp->arg[i].reg == NULL) {
			fprintf(f, "\tmovl %d(%%esp), %%eax\n",
				(i + sarg_ofs) * 4);
			fprintf(f, "\tpushl %%eax\n");
			sarg_ofs++;
			args_repushed++;
		}
	}

	// load arg regs
	for (i = 0; i < pp->argc; i++) {
		if (pp->arg[i].reg != NULL) {
			fprintf(f, "\tmovl %d(%%esp), %%%s\n",
				(i + sarg_ofs) * 4, pp->arg[i].reg);
			if (pp->arg[i].type.is_retreg)
				fprintf(f, "\tmovl (%%%s), %%%s\n",
					pp->arg[i].reg, pp->arg[i].reg);
		}
	}

	fprintf(f, "\n\t# %s\n", pp->is_stdcall ? "__stdcall" : "__cdecl");
	fprintf(f, "\tcall %s\n\n", sym_out);

	if (args_repushed && !pp->is_stdcall) {
		fprintf(f, "\tadd $%d,%%esp\n", args_repushed * 4);
		sarg_ofs -= args_repushed;
	}

	// update the retreg regs
	if (pp->has_retreg) {
		for (i = 0; i < pp->argc; i++) {
			if (pp->arg[i].type.is_retreg) {
				fprintf(f, "\tmovl %d(%%esp), %%ecx\n"
					   "\tmovl %%%s, (%%ecx)\n",
					(i + sarg_ofs) * 4, pp->arg[i].reg);
			}
		}
	}

	// restore regs
	for (i = ARRAY_SIZE(c_save_regs) - 1; i >= 0; i--)
		fprintf(f, "\tpopl %%%s\n", c_save_regs[i]);

	fprintf(f, "\tret\n\n");
}

static void out_fromasm_x86(FILE *f, const char *sym,
	const struct parsed_proto *pp)
{
	int reg_ofs[ARRAY_SIZE(pp->arg)];
	int sarg_ofs = 1; // stack offset to args, in DWORDs
	int saved_regs = 0;
	int ecx_ofs = -1;
	int edx_ofs = -1;
	int c_is_stdcall;
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
	if (!pp->is_fastcall && pp->argc_reg != 0)
		fprintf(f, " +reg");

	if (pp->is_stdcall && !pp->is_fastcall && pp->argc_reg != 0
	    && !IS_START(sym, "sub_") && !IS_START(sym, "f_"))
	{
		// alias for possible .def export
		char sym2[256];

		snprintf(sym2, sizeof(sym2), "_%s@%d",
			 sym, pp->argc * 4);
		fprintf(f, "\n.global %s # for .def\n", sym2);
		fprintf(f, "%s:", sym2);
	}
	fprintf(f, "\n.global %s\n", sym);
	fprintf(f, "%s:\n", sym);

	if ((pp->argc_reg == 0 || pp->is_fastcall)
	    && !IS(pp->name, "storm_491")) // wants edx save :(
	{
		fprintf(f, "\tjmp %s\n\n", pp_to_name(pp));
		return;
	}

	c_is_stdcall = (pp->argc_reg == 0 && pp->is_stdcall);

	// at least sc sub_47B150 needs edx to be preserved
	// int64 returns use edx:eax - no edx save
	// we use ecx also as scratch
	fprintf(f, "\tpushl %%ecx\n");
	saved_regs++;
	sarg_ofs++;
	ecx_ofs = sarg_ofs;
	if (!ret64) {
		fprintf(f, "\tpushl %%edx\n");
		saved_regs++;
		sarg_ofs++;
		edx_ofs = sarg_ofs;
	}

	// need space for retreg args
	if (pp->has_retreg) {
		for (i = 0; i < pp->argc; i++) {
			if (!pp->arg[i].type.is_retreg)
				continue;
			if (IS(pp->arg[i].reg, "ecx") && ecx_ofs >= 0) {
				reg_ofs[i] = ecx_ofs;
				continue;
			}
			if (IS(pp->arg[i].reg, "edx") && edx_ofs >= 0) {
				reg_ofs[i] = edx_ofs;
				continue;
			}
			fprintf(f, "\tpushl %%%s\n", pp->arg[i].reg);
			saved_regs++;
			sarg_ofs++;
			reg_ofs[i] = sarg_ofs;
		}
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
			const char *reg = pp->arg[i].reg;
			if (pp->arg[i].type.is_retreg) {
				reg = "ecx";
				fprintf(f, "\tlea %d(%%esp), %%ecx\n",
				  (sarg_ofs - reg_ofs[i]) * 4);
			}
			else if (IS(reg, "ecx"))
				// must reload original ecx
				fprintf(f, "\tmovl %d(%%esp), %%ecx\n",
					(sarg_ofs - 2) * 4);

			fprintf(f, "\tpushl %%%s\n", reg);
		}
		sarg_ofs++;
	}

	fprintf(f, "\n\tcall %s\n\n", pp_to_name(pp));

	if (!c_is_stdcall && sarg_ofs > saved_regs + 1)
		fprintf(f, "\tadd $%d,%%esp\n",
			(sarg_ofs - (saved_regs + 1)) * 4);

	// pop retregs
	if (pp->has_retreg) {
		for (i = pp->argc - 1; i >= 0; i--) {
			if (!pp->arg[i].type.is_retreg)
				continue;
			if (IS(pp->arg[i].reg, "ecx") && ecx_ofs >= 0) {
				continue;
			}
			if (IS(pp->arg[i].reg, "edx") && edx_ofs >= 0) {
				continue;
			}
			fprintf(f, "\tpopl %%%s\n", pp->arg[i].reg);
		}
	}

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
	fprintf(fout, "# C -> asm\n\n");

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

		out_toasm_x86(fout, sym_noat, pp);
	}

	fprintf(fout, "# asm -> C\n\n");

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
