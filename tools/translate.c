#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "my_assert.h"
#include "my_str.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define IS(w, y) !strcmp(w, y)

#include "protoparse.h"

const char *asmfn;
static int asmln;

#define awarn(fmt, ...) \
	printf("warning:%s:%d: " fmt, asmfn, asmln, ##__VA_ARGS__)
#define aerr(fmt, ...) do { \
	printf("error:%s:%d: " fmt, asmfn, asmln, ##__VA_ARGS__); \
	exit(1); \
} while (0)

enum op_class {
	OPC_UNSPEC,
	OPC_RMD,	/* removed or optimized out */
	OPC_DATA,	/* data processing */
	OPC_DATA_FLAGS,	/* data processing + sets flags */
	OPC_JMP,	/* .. and call */
	OPC_JCC,
};

enum op_op {
	OP_INVAL,
	OP_PUSH,
	OP_POP,
	OP_MOV,
	OP_RET,
	OP_ADD,
	OP_TEST,
	OP_CMP,
	OP_CALL,
	OP_JMP,
	OP_JO,
	OP_JNO,
	OP_JC,
	OP_JNC,
	OP_JZ,
	OP_JNZ,
	OP_JBE,
	OP_JA,
	OP_JS,
	OP_JNS,
	OP_JP,
	OP_JNP,
	OP_JL,
	OP_JGE,
	OP_JLE,
	OP_JG,
};

enum opr_type {
	OPT_UNSPEC,
	OPT_REG,
	OPT_REGMEM,
	OPT_LABEL,
	OPT_CONST,
};

enum opr_lenmod {
	OPRM_UNSPEC,
	OPRM_BYTE,
	OPRM_WORD,
	OPRM_DWORD,
};

#define MAX_OPERANDS 2

struct parsed_opr {
	enum opr_type type;
	enum opr_lenmod lmod;
	unsigned int val;
	char name[256];
};

struct parsed_op {
	enum op_class cls;
	enum op_op op;
	struct parsed_opr operand[MAX_OPERANDS];
	int operand_cnt;
};

#define MAX_OPS 1024

static struct parsed_op ops[MAX_OPS];
static char labels[MAX_OPS][32];

const char *main_regs[] = { "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp" };

static int parse_operand(struct parsed_opr *opr,
	char words[16][256], int wordc, int w, enum op_class cls)
{
	char *endp = NULL;
	int ret, len;
	int i;

	if (w >= wordc)
		aerr("parse_operand w %d, wordc %d\n", w, wordc);

	for (i = w; i < wordc; i++) {
		len = strlen(words[i]);
		if (words[i][len - 1] == ',') {
			words[i][len - 1] = 0;
			wordc = i + 1;
			break;
		}
	}

	if (cls == OPC_JMP || cls == OPC_JCC) {
		const char *label;

		if (wordc - w == 3 && IS(words[w + 1], "ptr"))
			label = words[w + 2];
		else if (wordc - w == 2 && IS(words[w], "short"))
			label = words[w + 1];
		else if (wordc - w == 1)
			label = words[w];
		else
			aerr("jump parse error");

		opr->type = OPT_LABEL;
		strcpy(opr->name, label);
		return wordc;
	}

	if (wordc - w >= 3) {
		if (IS(words[w + 1], "ptr")) {
			if (IS(words[w], "dword"))
				opr->lmod = OPRM_DWORD;
			else if (IS(words[w], "word"))
				opr->lmod = OPRM_WORD;
			else if (IS(words[w], "byte"))
				opr->lmod = OPRM_BYTE;
			else
				aerr("type parsing failed\n");
			w += 2;
		}
	}

	if (wordc - w == 2 && IS(words[w], "offset")) {
		opr->type = OPT_LABEL;
		strcpy(opr->name, words[w + 1]);
		return wordc;
	}

	if (wordc - w != 1)
		aerr("parse_operand 1 word expected\n");

	len = strlen(words[w]);

	if (words[w][0] == '[') {
		opr->type = OPT_REGMEM;
		ret = sscanf(words[w], "[%256s]", opr->name);
		if (ret != 1)
			aerr("[] parse failure\n");
		return wordc;
	}
	else if (('0' <= words[w][0] && words[w][0] <= '9')
		|| words[w][0] == '-')
	{
		opr->type = OPT_CONST;
		i = 0;
		if (len > 1 && words[w][0] == '0')
			i = 1;
		if (words[w][len - 1] == 'h') {
			words[w][len - 1] = 0;
			opr->val = strtoul(&words[w][i], &endp, 16);
		}
		else {
			opr->val = strtoul(&words[w][i], &endp, 10);
		}
		if (*endp != 0)
			aerr("const parse failed\n");
		return wordc;
	}

	strcpy(opr->name, words[w]);
	opr->type = OPT_REG;
	return wordc;
}

static const struct {
	const char *name;
	enum op_op op;
	enum op_class cls;
	int minopr;
	int maxopr;
} op_table[] = {
	{ "push", OP_PUSH,   OPC_DATA,       1, 1 },
	{ "pop",  OP_POP,    OPC_DATA,       1, 1 },
	{ "mov" , OP_MOV,    OPC_DATA,       2, 2 },
	{ "add",  OP_ADD,    OPC_DATA_FLAGS, 2, 2 },
	{ "test", OP_TEST,   OPC_DATA_FLAGS, 2, 2 },
	{ "cmp",  OP_CMP,    OPC_DATA_FLAGS, 2, 2 },
	{ "retn", OP_RET,    OPC_JMP,        0, 1 },
	{ "call", OP_CALL,   OPC_JMP,        1, 1 },
	{ "jmp",  OP_JMP,    OPC_JMP,        1, 1 },
	{ "jo",   OP_JO,     OPC_JCC,        1, 1 }, // 70 OF=1
	{ "jno",  OP_JNO,    OPC_JCC,        1, 1 }, // 71 OF=0
	{ "jc",   OP_JC,     OPC_JCC,        1, 1 }, // 72 CF=1
	{ "jb",   OP_JC,     OPC_JCC,        1, 1 }, // 72
	{ "jnc",  OP_JNC,    OPC_JCC,        1, 1 }, // 73 CF=0
	{ "jae",  OP_JNC,    OPC_JCC,        1, 1 }, // 73
	{ "jz",   OP_JZ,     OPC_JCC,        1, 1 }, // 74 ZF=1
	{ "je",   OP_JZ,     OPC_JCC,        1, 1 }, // 74
	{ "jnz",  OP_JNZ,    OPC_JCC,        1, 1 }, // 75 ZF=0
	{ "jne",  OP_JNZ,    OPC_JCC,        1, 1 }, // 75
	{ "jbe",  OP_JBE,    OPC_JCC,        1, 1 }, // 76 CF=1 || ZF=1
	{ "jna",  OP_JBE,    OPC_JCC,        1, 1 }, // 76
	{ "ja",   OP_JA,     OPC_JCC,        1, 1 }, // 77 CF=0 && ZF=0
	{ "jnbe", OP_JA,     OPC_JCC,        1, 1 }, // 77
	{ "js",   OP_JS,     OPC_JCC,        1, 1 }, // 78 SF=1
	{ "jns",  OP_JNS,    OPC_JCC,        1, 1 }, // 79 SF=0
	{ "jp",   OP_JP,     OPC_JCC,        1, 1 }, // 7a PF=1
	{ "jpe",  OP_JP,     OPC_JCC,        1, 1 }, // 7a
	{ "jnp",  OP_JNP,    OPC_JCC,        1, 1 }, // 7b PF=0
	{ "jpo",  OP_JNP,    OPC_JCC,        1, 1 }, // 7b
	{ "jl",   OP_JL,     OPC_JCC,        1, 1 }, // 7c SF!=OF
	{ "jnge", OP_JL,     OPC_JCC,        1, 1 }, // 7c
	{ "jge",  OP_JGE,    OPC_JCC,        1, 1 }, // 7d SF=OF
	{ "jnl",  OP_JGE,    OPC_JCC,        1, 1 }, // 7d
	{ "jle",  OP_JLE,    OPC_JCC,        1, 1 }, // 7e ZF=1 || SF!=OF
	{ "jng",  OP_JLE,    OPC_JCC,        1, 1 }, // 7e
	{ "jg",   OP_JG,     OPC_JCC,        1, 1 }, // 7f ZF=0 && SF=OF
	{ "jnle", OP_JG,     OPC_JCC,        1, 1 }, // 7f
};

static void parse_op(struct parsed_op *op, char words[16][256], int wordc)
{
	int w = 1;
	int opr;
	int i;

	for (i = 0; i < ARRAY_SIZE(op_table); i++) {
		if (!IS(words[0], op_table[i].name))
			continue;

		for (opr = 0; opr < op_table[i].minopr; opr++) {
			w = parse_operand(&op->operand[opr],
				words, wordc, w, op_table[i].cls);
		}

		for (; w < wordc && opr < op_table[i].maxopr; opr++) {
			w = parse_operand(&op->operand[opr],
				words, wordc, w, op_table[i].cls);
		}

		goto done;
	}

	aerr("unhandled op: '%s'\n", words[0]);

done:
	if (w < wordc)
		aerr("parse_op %s incomplete: %d/%d\n",
			words[0], w, wordc);

	op->cls = op_table[i].cls;
	op->op = op_table[i].op;
	return;
}

int gen_func(FILE *fout, FILE *fhdr, const char *funcn, int opcnt)
{
	struct parsed_proto pp;
	int ret;
	int i;

	ret = proto_parse(fhdr, funcn, &pp);
	if (ret)
		return ret;

	fprintf(fout, "%s %s(", pp.ret_type, funcn);
	for (i = 0; i < pp.argc; i++) {
		if (i > 0)
			fprintf(fout, ", ");
		fprintf(fout, "%s a%d", pp.arg[i].type, i);
	}
	fprintf(fout, ")\n{\n");



	fprintf(fout, "}\n\n");
	proto_release(&pp);
	return 0;
}

int main(int argc, char *argv[])
{
	FILE *fout, *fasm, *fhdr;
	char line[256];
	char words[16][256];
	char func[256];
	int in_func = 0;
	int pi = 0;
	int len;
	char *p;
	int wordc;

	if (argc != 4) {
		printf("usage:\n%s <.c> <.asm> <hdrf>\n",
			argv[0]);
		return 1;
	}

	hdrfn = argv[3];
	fhdr = fopen(hdrfn, "r");
	my_assert_not(fhdr, NULL);

	asmfn = argv[2];
	fasm = fopen(asmfn, "r");
	my_assert_not(fasm, NULL);

	fout = fopen(argv[1], "w");
	my_assert_not(fout, NULL);


	while (fgets(line, sizeof(line), fasm))
	{
		asmln++;

		p = sskip(line);
		if (*p == 0 || *p == ';')
			continue;

		memset(words, 0, sizeof(words));
		for (wordc = 0; wordc < 16; wordc++) {
			p = sskip(next_word(words[wordc], sizeof(words[0]), p));
			if (*p == 0 || *p == ';') {
				wordc++;
				break;
			}
		}

		if (wordc == 0) {
			// shouldn't happen
			awarn("wordc == 0?\n");
			continue;
		}

		// don't care about this:
		if (words[0][0] == '.'
		    || IS(words[0], "include")
		    || IS(words[0], "assume") || IS(words[1], "segment")
		    || IS(words[0], "align"))
		{
			continue;
		}

		if (IS(words[1], "proc")) {
			if (in_func)
				aerr("proc '%s' while in_func '%s'?\n",
					words[0], func);
			strcpy(func, words[0]);
			in_func = 1;
			continue;
		}

		if (IS(words[1], "endp")) {
			if (!in_func)
				aerr("endp '%s' while not in_func?\n", words[0]);
			if (!IS(func, words[0]))
				aerr("endp '%s' while in_func '%s'?\n",
					words[0], func);
			gen_func(fout, fhdr, func, pi);
			in_func = 0;
			func[0] = 0;
			if (pi != 0) {
				memset(&ops, 0, pi * sizeof(ops[0]));
				memset(labels, 0, pi * sizeof(labels[0]));
				pi = 0;
			}
			exit(1);
			continue;
		}

		if (IS(words[1], "="))
			// lots of work will be have to be done here, but for now..
			continue;

		if (pi >= ARRAY_SIZE(ops))
			aerr("too many ops\n");

		p = strchr(words[0], ':');
		if (p != NULL) {
			len = p - words[0];
			if (len > sizeof(labels[0]) - 1)
				aerr("label too long: %d\n", len);
			if (labels[pi][0] != 0)
				aerr("dupe label?\n");
			memcpy(labels[pi], words[0], len);
			labels[pi][len] = 0;
			continue;
		}

		parse_op(&ops[pi], words, wordc);
		pi++;

		(void)proto_parse;
	}

	fclose(fout);
	fclose(fasm);
	fclose(fhdr);

	return 0;
}
