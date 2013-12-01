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
	OPC_RMD,        /* removed or optimized out */
	OPC_DATA,       /* data processing */
	OPC_DATA_FLAGS, /* data processing + sets flags */
	OPC_JMP,        /* .. and call */
	OPC_JCC,        /* conditional jump */
	OPC_SCC,        /* conditionel set */
};

enum op_op {
	OP_INVAL,
	OP_PUSH,
	OP_POP,
	OP_MOV,
	OP_LEA,
	OP_MOVZX,
	OP_MOVSX,
	OP_NOT,
	OP_RET,
	OP_ADD,
	OP_SUB,
	OP_AND,
	OP_OR,
	OP_XOR,
	OP_SHL,
	OP_SHR,
	OP_SAR,
	OP_SBB,
	OP_INC,
	OP_DEC,
	OP_MUL,
	OP_IMUL,
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
  OPT_OFFSET,
	OPT_CONST,
};

enum opr_lenmod {
	OPLM_UNSPEC,
	OPLM_BYTE,
	OPLM_WORD,
	OPLM_DWORD,
};

#define MAX_OPERANDS 3

struct parsed_opr {
  enum opr_type type;
  enum opr_lenmod lmod;
  int reg;
  unsigned int val;
  char name[256];
};

struct parsed_op {
  enum op_class cls;
  enum op_op op;
  struct parsed_opr operand[MAX_OPERANDS];
  int operand_cnt;
  int regmask;        // all referensed regs
  void *datap;
};

struct parsed_equ {
  char name[64];
  enum opr_lenmod lmod;
  int offset;
};

#define MAX_OPS 1024

static struct parsed_op ops[MAX_OPS];
static struct parsed_equ *g_eqs;
static int g_eqcnt;
static char g_labels[MAX_OPS][32];
static struct parsed_proto g_func_pp;
static char g_func[256];
static char g_comment[256];
static int g_bp_frame;
static int g_bp_stack;
#define ferr(op_, fmt, ...) do { \
  printf("error:%s:#%ld: '%s': " fmt, g_func, (op_) - ops, \
    dump_op(op_), ##__VA_ARGS__); \
  exit(1); \
} while (0)

#define MAX_REGS 8

const char *regs_r32[] = { "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp" };
const char *regs_r16[] = { "ax", "bx", "cx", "dx", "si", "di", "bp", "sp" };
const char *regs_r8l[] = { "al", "bl", "cl", "dl" };
const char *regs_r8h[] = { "ah", "bh", "ch", "dh" };

enum x86_regs { xUNSPEC = -1, xAX, xBX, xCX, xDX, xSI, xDI, xBP, xSP };

static int char_array_i(const char *array[], size_t len, const char *s)
{
  int i;

  for (i = 0; i < len; i++)
    if (IS(s, array[i]))
      return i;

  return -1;
}

static int parse_reg(int *reg_out, enum opr_lenmod *reg_lmod,
  int *regmask, char *s)
{
  char w[16];
  int reg = xUNSPEC;
  int c = 0;

  while (*s != 0) {
    while (my_isblank(*s) || my_issep(*s))
      s++;
    s = next_idt(w, sizeof(w), s);
    if (w[0] == 0)
      break;
    c++;
    reg = char_array_i(regs_r32, ARRAY_SIZE(regs_r32), w);
    if (reg >= 0) {
      *reg_lmod = OPLM_DWORD;
      *regmask |= 1 << reg;
      continue;
    }
    reg = char_array_i(regs_r16, ARRAY_SIZE(regs_r16), w);
    if (reg >= 0) {
      *reg_lmod = OPLM_WORD;
      *regmask |= 1 << reg;
      continue;
    }
    reg = char_array_i(regs_r8h, ARRAY_SIZE(regs_r8h), w);
    if (reg >= 0) {
      *reg_lmod = OPLM_BYTE;
      *regmask |= 1 << reg;
      continue;
    }
    reg = char_array_i(regs_r8l, ARRAY_SIZE(regs_r8l), w);
    if (reg >= 0) {
      *reg_lmod = OPLM_BYTE;
      *regmask |= 1 << reg;
      continue;
    }

    return -1;
  }

  if (c == 1) {
    *reg_out = reg;
    return 0;
  }

  return -1;
}

static long parse_number(const char *number)
{
  int len = strlen(number);
  const char *p = number;
  char *endp = NULL;
  int neg = 0;
  int bad;
  long ret;

  if (*p == '-') {
    neg = 1;
    p++;
  }
  if (len > 1 && *p == '0')
    p++;
  if (number[len - 1] == 'h') {
    ret = strtol(p, &endp, 16);
    bad = (*endp != 'h');
  }
  else {
    ret = strtol(p, &endp, 10);
    bad = (*endp != 0);
  }
  if (bad)
    aerr("number parsing failed\n");
  if (neg)
    ret = -ret;
  return ret;
}

static int guess_lmod_from_name(struct parsed_opr *opr)
{
  if (!strncmp(opr->name, "dword_", 6)) {
    opr->lmod = OPLM_DWORD;
    return 1;
  }
  if (!strncmp(opr->name, "word_", 5)) {
    opr->lmod = OPLM_WORD;
    return 1;
  }
  if (!strncmp(opr->name, "byte_", 5)) {
    opr->lmod = OPLM_BYTE;
    return 1;
  }
  return 0;
}

static int parse_operand(struct parsed_opr *opr, int *regmask,
	char words[16][256], int wordc, int w, enum op_class cls)
{
  enum opr_lenmod tmplmod;
  int tmpreg;
  int ret, len;
  int i;

	if (w >= wordc)
		aerr("parse_operand w %d, wordc %d\n", w, wordc);

	opr->reg = xUNSPEC;

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
				opr->lmod = OPLM_DWORD;
			else if (IS(words[w], "word"))
				opr->lmod = OPLM_WORD;
			else if (IS(words[w], "byte"))
				opr->lmod = OPLM_BYTE;
			else
				aerr("type parsing failed\n");
			w += 2;
		}
	}

	if (wordc - w == 2 && IS(words[w], "offset")) {
		opr->type = OPT_OFFSET;
		strcpy(opr->name, words[w + 1]);
		return wordc;
	}

  if (wordc - w != 1)
    aerr("parse_operand 1 word expected\n");

  strcpy(opr->name, words[w]);

  if (words[w][0] == '[') {
    opr->type = OPT_REGMEM;
    ret = sscanf(words[w], "[%[^]]]", opr->name);
    if (ret != 1)
      aerr("[] parse failure\n");
    // only need the regmask
    parse_reg(&tmpreg, &tmplmod, regmask, opr->name);
    return wordc;
  }
  else if (strchr(words[w], '[')) {
    // label[reg] form
    opr->type = OPT_REGMEM;
    if (opr->lmod == OPLM_UNSPEC)
      guess_lmod_from_name(opr);
    parse_reg(&tmpreg, &tmplmod, regmask, strchr(words[w], '['));
    return wordc;
  }
  else if (('0' <= words[w][0] && words[w][0] <= '9')
    || words[w][0] == '-')
  {
    opr->type = OPT_CONST;
    opr->val = (unsigned int)parse_number(words[w]);
    return wordc;
  }

  ret = parse_reg(&opr->reg, &tmplmod, regmask, opr->name);
  if (ret == 0) {
    opr->type = OPT_REG;
    opr->lmod = tmplmod;
    return wordc;
  }

  // most likely var in data segment
  opr->type = OPT_LABEL;
  if (opr->lmod == OPLM_UNSPEC)
    guess_lmod_from_name(opr);
  if (opr->lmod != OPLM_UNSPEC)
    return wordc;

  // TODO: scan data seg to determine type?
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
  { "lea",  OP_LEA,    OPC_DATA,       2, 2 },
  { "movzx",OP_MOVZX,  OPC_DATA,       2, 2 },
  { "movsx",OP_MOVSX,  OPC_DATA,       2, 2 },
  { "not",  OP_NOT,    OPC_DATA,       1, 1 },
  { "add",  OP_ADD,    OPC_DATA_FLAGS, 2, 2 },
  { "sub",  OP_SUB,    OPC_DATA_FLAGS, 2, 2 },
  { "and",  OP_AND,    OPC_DATA_FLAGS, 2, 2 },
  { "or",   OP_OR,     OPC_DATA_FLAGS, 2, 2 },
  { "xor",  OP_XOR,    OPC_DATA_FLAGS, 2, 2 },
  { "shl",  OP_SHL,    OPC_DATA_FLAGS, 2, 2 },
  { "shr",  OP_SHR,    OPC_DATA_FLAGS, 2, 2 },
  { "sal",  OP_SHL,    OPC_DATA_FLAGS, 2, 2 },
  { "sar",  OP_SAR,    OPC_DATA_FLAGS, 2, 2 },
  { "sbb",  OP_SBB,    OPC_DATA_FLAGS, 2, 2 },
  { "inc",  OP_INC,    OPC_DATA_FLAGS, 1, 1 },
  { "dec",  OP_DEC,    OPC_DATA_FLAGS, 1, 1 },
  { "mul",  OP_MUL,    OPC_DATA_FLAGS, 1, 1 },
  { "imul", OP_IMUL,   OPC_DATA_FLAGS, 1, 3 },
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
  int opr = 0;
  int w = 1;
  int i;

  for (i = 0; i < ARRAY_SIZE(op_table); i++) {
    if (!IS(words[0], op_table[i].name))
      continue;

    op->regmask = 0;

    for (opr = 0; opr < op_table[i].minopr; opr++) {
      w = parse_operand(&op->operand[opr], &op->regmask,
        words, wordc, w, op_table[i].cls);
    }

    for (; w < wordc && opr < op_table[i].maxopr; opr++) {
      w = parse_operand(&op->operand[opr], &op->regmask,
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
  op->operand_cnt = opr;
  return;
}

static const char *op_name(enum op_op op)
{
  int i;

  for (i = 0; i < ARRAY_SIZE(op_table); i++)
    if (op_table[i].op == op)
      return op_table[i].name;

  return "???";
}

// debug
static const char *dump_op(struct parsed_op *po)
{
  static char out[128];
  char *p = out;
  int i;

  snprintf(out, sizeof(out), "%s", op_name(po->op));
  for (i = 0; i < po->operand_cnt; i++) {
    p += strlen(p);
    if (i > 0)
      *p++ = ',';
    snprintf(p, sizeof(out) - (p - out),
      po->operand[i].type == OPT_REGMEM ? " [%s]" : " %s",
      po->operand[i].name);
  }

  return out;
}

static const char *opr_name(struct parsed_op *po, int opr_num)
{
  if (opr_num >= po->operand_cnt)
    ferr(po, "opr OOR: %d/%d\n", opr_num, po->operand_cnt);
  return po->operand[opr_num].name;
}

static unsigned int opr_const(struct parsed_op *po, int opr_num)
{
  if (opr_num >= po->operand_cnt)
    ferr(po, "opr OOR: %d/%d\n", opr_num, po->operand_cnt);
  if (po->operand[opr_num].type != OPT_CONST)
    ferr(po, "opr %d: const expected\n", opr_num);
  return po->operand[opr_num].val;
}

static const char *opr_reg_p(struct parsed_op *po, struct parsed_opr *popr)
{
  if ((unsigned int)popr->reg >= MAX_REGS)
    ferr(po, "invalid reg: %d\n", popr->reg);
  return regs_r32[popr->reg];
}

static struct parsed_equ *equ_find(struct parsed_op *po, const char *name)
{
  int i;

  for (i = 0; i < g_eqcnt; i++)
    if (IS(g_eqs[i].name, name))
      break;
  if (i >= g_eqcnt)
    ferr(po, "unresolved equ name: '%s'\n", name);

  return &g_eqs[i];
}

static void bg_frame_access(struct parsed_op *po, enum opr_lenmod lmod,
  char *buf, size_t buf_size, const char *bp_arg,
  int is_src, int is_lea)
{
  const char *prefix = "";
  struct parsed_equ *eq;
  int i, arg_i, arg_s;
  int sf_ofs;

  snprintf(g_comment, sizeof(g_comment), "%s", bp_arg);

  eq = equ_find(po, bp_arg);

  if (eq->offset >= 0) {
    arg_i = eq->offset / 4 - 2;
    if (arg_i < 0 || arg_i >= g_func_pp.argc_stack)
      ferr(po, "offset %d doesn't map to any arg\n", eq->offset);

    for (i = arg_s = 0; i < g_func_pp.argc; i++) {
      if (g_func_pp.arg[i].reg != NULL)
        continue;
      if (arg_s == arg_i)
        break;
      arg_s++;
    }
    if (i == g_func_pp.argc)
      ferr(po, "arg %d not in prototype?\n", arg_i);
    if (is_lea)
      ferr(po, "lea to arg?\n");

    snprintf(buf, buf_size, "%sa%d", is_src ? "(u32)" : "", i + 1);
  }
  else {
    if (g_bp_stack == 0)
      ferr(po, "bp_stack access after it was not detected\n");

    sf_ofs = g_bp_stack + eq->offset;
    if (sf_ofs < 0)
      ferr(po, "bp_stack offset %d/%d\n", eq->offset, g_bp_stack);

    if (is_lea)
      prefix = "&";

    switch (lmod)
    {
    case OPLM_BYTE:
      snprintf(buf, buf_size, "%ssf.b[%d]", prefix, sf_ofs);
      break;
    case OPLM_WORD:
      snprintf(buf, buf_size, "%ssf.w[%d]", prefix, sf_ofs / 2);
      break;
    case OPLM_DWORD:
      snprintf(buf, buf_size, "%ssf.d[%d]", prefix, sf_ofs / 4);
      break;
    default:
      ferr(po, "bp_stack bad lmod: %d\n", lmod);
    }
  }
}

static char *out_src_opr(char *buf, size_t buf_size,
	struct parsed_op *po, struct parsed_opr *popr, int is_lea)
{
  const char *cast = "";
  char tmp1[256], tmp2[256];
  char expr[256];
  int ret;

  switch (popr->type) {
  case OPT_REG:
    if (is_lea)
      ferr(po, "lea from reg?\n");

    switch (popr->lmod) {
    case OPLM_DWORD:
      snprintf(buf, buf_size, "%s", opr_reg_p(po, popr));
      break;
    case OPLM_WORD:
      snprintf(buf, buf_size, "(u16)%s", opr_reg_p(po, popr));
      break;
    case OPLM_BYTE:
      snprintf(buf, buf_size, "(u8)%s", opr_reg_p(po, popr));
      break;
    default:
      ferr(po, "invalid src lmod: %d\n", popr->lmod);
    }
    break;

  case OPT_REGMEM:
    if (g_bp_frame && !strncmp(popr->name, "ebp+", 4)) {
      bg_frame_access(po, popr->lmod, buf, buf_size,
        popr->name + 4, 1, is_lea);
      break;
    }

    strcpy(expr, popr->name);
    if (strchr(expr, '[')) {
      // special case: '[' can only be left for label[reg] form
      ret = sscanf(expr, "%[^[][%[^]]]", tmp1, tmp2);
      if (ret != 2)
        ferr(po, "parse failure for '%s'\n", expr);
      snprintf(expr, sizeof(expr), "(u32)%s + %s", tmp1, tmp2);
    }

    // XXX: do we need more parsing?
    if (is_lea) {
      snprintf(buf, buf_size, "%s", expr);
      break;
    }

    switch (popr->lmod) {
    case OPLM_DWORD:
      cast = "*(u32 *)";
      break;
    case OPLM_WORD:
      cast = "*(u16 *)";
      break;
    case OPLM_BYTE:
      cast = "*(u8 *)";
      break;
    default:
      ferr(po, "invalid lmod: %d\n", popr->lmod);
    }
    snprintf(buf, buf_size, "%s(%s)", cast, expr);
    break;

  case OPT_LABEL:
    if (is_lea)
      snprintf(buf, buf_size, "(u32)&%s", popr->name);
    else
      snprintf(buf, buf_size, "%s", popr->name);
    break;

  case OPT_OFFSET:
    if (is_lea)
      ferr(po, "lea an offset?\n");
    snprintf(buf, buf_size, "(u32)&%s", popr->name);
    break;

  case OPT_CONST:
    if (is_lea)
      ferr(po, "lea from const?\n");

    snprintf(buf, buf_size, popr->val < 10 ? "%u" : "0x%02x", popr->val);
    break;

  default:
    ferr(po, "invalid src type: %d\n", popr->type);
  }

  return buf;
}

static char *out_dst_opr(char *buf, size_t buf_size,
	struct parsed_op *po, struct parsed_opr *popr)
{
  switch (popr->type) {
  case OPT_REG:
    switch (popr->lmod) {
    case OPLM_DWORD:
      snprintf(buf, buf_size, "%s", opr_reg_p(po, popr));
      break;
    case OPLM_WORD:
      // ugh..
      snprintf(buf, buf_size, "LOWORD(%s)", opr_reg_p(po, popr));
      break;
    case OPLM_BYTE:
      // ugh..
      snprintf(buf, buf_size, "LOBYTE(%s)", opr_reg_p(po, popr));
      break;
    default:
      ferr(po, "invalid dst lmod: %d\n", popr->lmod);
    }
    break;

  case OPT_REGMEM:
    if (g_bp_frame && !strncmp(popr->name, "ebp+", 4)) {
      bg_frame_access(po, popr->lmod, buf, buf_size,
        popr->name + 4, 0, 0);
      break;
    }

    return out_src_opr(buf, buf_size, po, popr, 0);

  default:
    ferr(po, "invalid dst type: %d\n", popr->type);
  }

  return buf;
}

static void split_cond(struct parsed_op *po, enum op_op *op, int *is_neg)
{
  *is_neg = 0;

  switch (*op) {
  case OP_JNO:
    *op = OP_JO;
    *is_neg = 1;
    break;
  case OP_JNC:
    *op = OP_JC;
    *is_neg = 1;
    break;
  case OP_JNZ:
    *op = OP_JZ;
    *is_neg = 1;
    break;
  case OP_JNS:
    *op = OP_JS;
    *is_neg = 1;
    break;
  case OP_JNP:
    *op = OP_JP;
    *is_neg = 1;
    break;
  case OP_JLE:
    *op = OP_JG;
    *is_neg = 1;
    break;
  case OP_JGE:
    *op = OP_JL;
    *is_neg = 1;
    break;
  case OP_JA:
    *op = OP_JBE;
    *is_neg = 1;
    break;
  case OP_JO:
  case OP_JC:
  case OP_JZ:
  case OP_JS:
  case OP_JP:
  case OP_JG:
  case OP_JL:
  case OP_JBE:
    break;
    //break;
  default:
    ferr(po, "split_cond: bad op %d\n", *op);
    break;
  }
}

static void out_test_for_cc(char *buf, size_t buf_size,
  struct parsed_op *po, enum op_op op, enum opr_lenmod lmod,
  const char *expr)
{
  const char *cast = "";
  int is_neg = 0;

  split_cond(po, &op, &is_neg);
  switch (op) {
  case OP_JZ:
    switch (lmod) {
    case OPLM_DWORD:
      break;
    case OPLM_WORD:
      cast = "(u16)";
      break;
    case OPLM_BYTE:
      cast = "(u8)";
      break;
    default:
      ferr(po, "%s: invalid lmod for JZ: %d\n", __func__, lmod);
    }
    snprintf(buf, buf_size, "(%s%s %s 0)",
      cast, expr, is_neg ? "!=" : "==");
    break;

  case OP_JG: // ZF=0 && SF=OF; OF=0 after test
    switch (lmod) {
    case OPLM_DWORD:
      snprintf(buf, buf_size, "((int)%s %s 0)", expr, is_neg ? "<=" : ">");
      break;
    default:
      ferr(po, "%s: unhandled lmod for JG: %d\n", __func__, lmod);
    }
    break;

  default:
    ferr(po, "%s: unhandled op: %d\n", __func__, op);
  }
}

static void out_cmp_for_cc(char *buf, size_t buf_size,
  struct parsed_op *po, enum op_op op, enum opr_lenmod lmod,
  const char *expr1, const char *expr2)
{
  const char *cast = "";
  const char *scast = "";
  int is_neg = 0;

  switch (lmod) {
  case OPLM_DWORD:
    scast = "(s32)";
    break;
  case OPLM_WORD:
    cast = "(u16)";
    scast = "(s16)";
    break;
  case OPLM_BYTE:
    cast = "(u8)";
    scast = "(s8)";
    break;
  default:
    ferr(po, "%s: invalid lmod: %d\n", __func__, lmod);
  }

  split_cond(po, &op, &is_neg);
  switch (op) {
  case OP_JZ:
    snprintf(buf, buf_size, "(%s%s %s %s%s)",
      cast, expr1, is_neg ? "!=" : "==", cast, expr2);
    break;

  case OP_JC:
    // note: must be unsigned compare
    snprintf(buf, buf_size, "(%s%s %s %s%s)",
      cast, expr1, is_neg ? ">=" : "<", cast, expr2);
    break;

  case OP_JL:
    // note: must be unsigned compare
    snprintf(buf, buf_size, "(%s%s %s %s%s)",
      scast, expr1, is_neg ? ">=" : "<", scast, expr2);
    break;

  default:
    ferr(po, "%s: unhandled op: %d\n", __func__, op);
  }
}

static void propagate_lmod(struct parsed_op *po, struct parsed_opr *popr1,
	struct parsed_opr *popr2)
{
  struct parsed_equ *eq;

  if (popr1->lmod == OPLM_UNSPEC && popr2->lmod == OPLM_UNSPEC) {
    // lmod could be specified by equ..
    if (!strncmp(popr1->name, "ebp+", 4)) {
      eq = equ_find(po, popr1->name + 4);
      popr1->lmod = eq->lmod;
    }
    if (!strncmp(popr2->name, "ebp+", 4)) {
      eq = equ_find(po, popr2->name + 4);
      popr2->lmod = eq->lmod;
    }
  }

  if (popr1->lmod == OPLM_UNSPEC && popr2->lmod == OPLM_UNSPEC)
    ferr(po, "missing lmod for both operands\n");

  if (popr1->lmod == OPLM_UNSPEC)
    popr1->lmod = popr2->lmod;
  else if (popr2->lmod == OPLM_UNSPEC)
    popr2->lmod = popr1->lmod;
  else if (popr1->lmod != popr2->lmod)
    ferr(po, "conflicting lmods: %d vs %d\n", popr1->lmod, popr2->lmod);
}

static const char *op_to_c(struct parsed_op *po)
{
  switch (po->op)
  {
    case OP_ADD:
      return "+";
    case OP_SUB:
      return "-";
    case OP_AND:
      return "&";
    case OP_OR:
      return "|";
    case OP_XOR:
      return "^";
    case OP_SHL:
      return "<<";
    case OP_SHR:
      return ">>";
    case OP_MUL:
    case OP_IMUL:
      return "*";
    default:
      ferr(po, "op_to_c was supplied with %d\n", po->op);
  }
}

static int scan_for_pop(int i, int opcnt, const char *reg)
{
  for (; i < opcnt; i++) {
    if (ops[i].cls == OPC_RMD)
      continue;

    if (ops[i].cls == OPC_JMP || ops[i].cls == OPC_JCC
        || g_labels[i][0] != 0)
      return -1;

    if (ops[i].op == OP_POP && ops[i].operand[0].type == OPT_REG
        && IS(ops[i].operand[0].name, reg))
      return i;
  }

  return -1;
}

// scan for pop starting from ret
static int scan_for_pop_ret(int i, int opcnt, const char *reg, int do_patch)
{
  int found = 0;
  int j;

  for (; i < opcnt; i++) {
    if (ops[i].op != OP_RET)
      continue;

    for (j = i - 1; j >= 0; j--) {
      if (ops[j].cls == OPC_JMP || ops[j].cls == OPC_JCC)
        return -1;

      if (ops[j].op == OP_POP && ops[j].operand[0].type == OPT_REG
          && IS(ops[j].operand[0].name, reg))
      {
        found = 1;
        if (do_patch)
          ops[j].cls = OPC_RMD;
        break;
      }

      if (g_labels[j][0] != 0)
        return -1;
    }
  }

  return found ? 0 : -1;
}

static void gen_func(FILE *fout, FILE *fhdr, const char *funcn, int opcnt)
{
  struct parsed_op *po, *delayed_op = NULL, *tmp_op;
  struct parsed_opr *last_arith_dst = NULL;
  char buf1[256], buf2[256], buf3[256];
  struct parsed_proto *pp;
  const char *tmpname;
  int had_decl = 0;
  int regmask_arg = 0;
  int regmask = 0;
  int special_sbb;
  int no_output;
  int arg;
  int i, j;
  int reg;
  int ret;

  g_bp_frame = g_bp_stack = 0;

  ret = proto_parse(fhdr, funcn, &g_func_pp);
  if (ret)
    ferr(ops, "proto_parse failed for '%s'\n", funcn);

  fprintf(fout, "%s %s(", g_func_pp.ret_type, funcn);
  for (i = 0; i < g_func_pp.argc; i++) {
    if (i > 0)
      fprintf(fout, ", ");
    fprintf(fout, "%s a%d", g_func_pp.arg[i].type, i + 1);
  }
  fprintf(fout, ")\n{\n");

  // pass1:
  // - handle ebp frame, remove ops related to it
  if (ops[0].op == OP_PUSH && IS(opr_name(&ops[0], 0), "ebp")
      && ops[1].op == OP_MOV
      && IS(opr_name(&ops[1], 0), "ebp")
      && IS(opr_name(&ops[1], 1), "esp"))
  {
    g_bp_frame = 1;
    ops[0].cls = OPC_RMD;
    ops[1].cls = OPC_RMD;

    if (ops[2].op == OP_SUB && IS(opr_name(&ops[2], 0), "esp")) {
      g_bp_stack = opr_const(&ops[2], 1);
      ops[2].cls = OPC_RMD;
    }

    i = 2;
    do {
      for (; i < opcnt; i++)
        if (ops[i].op == OP_RET)
          break;
      if (ops[i - 1].op != OP_POP || !IS(opr_name(&ops[i - 1], 0), "ebp"))
        ferr(&ops[i - 1], "'pop ebp' expected\n");
      ops[i - 1].cls = OPC_RMD;

      if (g_bp_stack != 0) {
        if (ops[i - 2].op != OP_MOV
            || !IS(opr_name(&ops[i - 2], 0), "esp")
            || !IS(opr_name(&ops[i - 2], 1), "ebp"))
        {
          ferr(&ops[i - 2], "esp restore expected\n");
        }
        ops[i - 2].cls = OPC_RMD;
      }
      i++;
    } while (i < opcnt);
  }

  // pass2:
  // - scan for all used registers
  // - process calls
  // - find POPs for PUSHes, rm both
  for (i = 0; i < opcnt; i++) {
    if (ops[i].cls == OPC_RMD)
      continue;

    if (ops[i].op == OP_PUSH && ops[i].operand[0].type == OPT_REG) {
      if (ops[i].operand[0].reg < 0)
        ferr(&ops[i], "reg not set for push?\n");
      if (!(regmask & (1 << ops[i].operand[0].reg))) { // reg save
        ret = scan_for_pop(i + 1, opcnt, ops[i].operand[0].name);
        if (ret >= 0) {
          ops[i].cls = ops[ret].cls = OPC_RMD;
          continue;
        }
        ret = scan_for_pop_ret(i + 1, opcnt, ops[i].operand[0].name, 0);
        if (ret == 0) {
          ops[i].cls = OPC_RMD;
          scan_for_pop_ret(i + 1, opcnt, ops[i].operand[0].name, 1);
          continue;
        }
      }
    }

    regmask |= ops[i].regmask;

    if (ops[i].op == OP_CALL) {
      pp = malloc(sizeof(*pp));
      my_assert_not(pp, NULL);
      tmpname = opr_name(&ops[i], 0);
      ret = proto_parse(fhdr, tmpname, pp);
      if (ret)
        ferr(&ops[i], "proto_parse failed for '%s'\n", tmpname);

      for (arg = 0; arg < pp->argc; arg++)
        if (pp->arg[arg].reg == NULL)
          break;

      for (j = i - 1; j >= 0 && arg < pp->argc; j--) {
        if (ops[j].cls == OPC_RMD)
          continue;
        if (ops[j].op != OP_PUSH)
          continue;

        pp->arg[arg].datap = &ops[j];
        ops[j].cls = OPC_RMD;
        for (arg++; arg < pp->argc; arg++)
          if (pp->arg[arg].reg == NULL)
            break;
      }
      if (arg < pp->argc)
        ferr(&ops[i], "arg collect failed for '%s'\n", tmpname);
      ops[i].datap = pp;
    }
  }

  // declare stack frame
  if (g_bp_stack)
    fprintf(fout, "  union { u32 d[%d]; u16 w[%d]; u8 b[%d]; } sf;\n",
      (g_bp_stack + 3) / 4, (g_bp_stack + 1) / 2, g_bp_stack);

  // instantiate arg-registers
  for (i = 0; i < g_func_pp.argc; i++) {
    if (g_func_pp.arg[i].reg != NULL) {
      reg = char_array_i(regs_r32,
              ARRAY_SIZE(regs_r32), g_func_pp.arg[i].reg);
      if (reg < 0)
        ferr(ops, "arg '%s' is not a reg?\n", g_func_pp.arg[i].reg);

      regmask_arg |= 1 << reg;
      fprintf(fout, "  u32 %s = (u32)a%d;\n",
        g_func_pp.arg[i].reg, i + 1);
      had_decl = 1;
    }
  }

  // instantiate other regs - special case for eax
  if (!((regmask | regmask_arg) & 1) && !IS(g_func_pp.ret_type, "void")) {
    fprintf(fout, "  u32 eax = 0;\n");
    had_decl = 1;
  }

  regmask &= ~regmask_arg;
  if (g_bp_frame)
    regmask &= ~(1 << xBP);
  if (regmask) {
    for (reg = 0; reg < 8; reg++) {
      if (regmask & (1 << reg)) {
        fprintf(fout, "  u32 %s;\n", regs_r32[reg]);
        had_decl = 1;
      }
    }
  }

  if (had_decl)
    fprintf(fout, "\n");

  // output ops
  for (i = 0; i < opcnt; i++) {
    if (g_labels[i][0] != 0)
      fprintf(fout, "\n%s:\n", g_labels[i]);

    if (ops[i].cls == OPC_RMD)
      continue;

    po = &ops[i];
    no_output = 0;

    #define assert_operand_cnt(n_) \
      if (po->operand_cnt != n_) \
        ferr(po, "operand_cnt is %d/%d\n", po->operand_cnt, n_)

    if (last_arith_dst != NULL && po->operand_cnt > 0
      && po->operand[0].type == OPT_REG)
    {
      if (IS(last_arith_dst->name, po->operand[0].name))
        last_arith_dst = NULL;
    }

    // conditional op?
    special_sbb = 0;
    if (po->op == OP_SBB && IS(opr_name(po, 0), opr_name(po, 1)))
      special_sbb = 1;

    if (po->cls == OPC_JCC || po->cls == OPC_SCC || special_sbb)
    {
      enum op_op flag_op = po->op;
      if (special_sbb)
        flag_op = OP_JC;

      if (delayed_op != NULL)
      {
        if (delayed_op->op == OP_TEST) {
          if (IS(opr_name(delayed_op, 0), opr_name(delayed_op, 1))) {
            out_src_opr(buf3, sizeof(buf3), delayed_op,
              &delayed_op->operand[0], 0);
          }
          else {
            out_src_opr(buf1, sizeof(buf1), delayed_op,
              &delayed_op->operand[0], 0);
            out_src_opr(buf2, sizeof(buf2), delayed_op,
              &delayed_op->operand[1], 0);
            snprintf(buf3, sizeof(buf3), "(%s & %s)", buf1, buf2);
          }
          out_test_for_cc(buf1, sizeof(buf1), po, flag_op,
            delayed_op->operand[0].lmod, buf3);
        }
        else if (delayed_op->op == OP_CMP) {
          out_src_opr(buf2, sizeof(buf2), delayed_op,
            &delayed_op->operand[0], 0);
          out_src_opr(buf3, sizeof(buf3), delayed_op,
            &delayed_op->operand[1], 0);
          out_cmp_for_cc(buf1, sizeof(buf1), po, flag_op,
            delayed_op->operand[0].lmod, buf2, buf3);
        }
      }
      else if (last_arith_dst != NULL
        && (flag_op == OP_JZ || flag_op == OP_JNZ))
      {
        out_src_opr(buf3, sizeof(buf3), po, last_arith_dst, 0);
        out_test_for_cc(buf1, sizeof(buf1), po, flag_op,
          last_arith_dst->lmod, buf3);
      }
      else
        ferr(po, "no delayed_op or last arith result before cond op\n");
 
      if (po->cls == OPC_JCC) {
        fprintf(fout, "  if %s\n", buf1);
      }
      else if (special_sbb) {
        out_dst_opr(buf2, sizeof(buf2), po, &po->operand[0]);
        fprintf(fout, "  %s = %s * -1;", buf2, buf1);
      }
      else {
        out_dst_opr(buf2, sizeof(buf2), po, &po->operand[0]);
        fprintf(fout, "  %s = %s;", buf2, buf1);
      }
    }

    switch (po->op)
    {
      case OP_MOV:
        assert_operand_cnt(2);
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        fprintf(fout, "  %s = %s;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
            out_src_opr(buf2, sizeof(buf2), po, &po->operand[1], 0));
        break;

      case OP_LEA:
        assert_operand_cnt(2);
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        fprintf(fout, "  %s = %s;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
            out_src_opr(buf2, sizeof(buf2), po, &po->operand[1], 1));
        break;

      case OP_MOVZX:
        assert_operand_cnt(2);
        fprintf(fout, "  %s = %s;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
            out_src_opr(buf2, sizeof(buf2), po, &po->operand[1], 0));
        break;

      case OP_MOVSX:
        assert_operand_cnt(2);
        switch (po->operand[1].lmod) {
        case OPLM_BYTE:
          strcpy(buf3, "(s8)");
          break;
        case OPLM_WORD:
          strcpy(buf3, "(s16)");
          break;
        default:
          ferr(po, "invalid src lmod: %d\n", po->operand[1].lmod);
        }
        fprintf(fout, "  %s = %s%s;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
            buf3,
            out_src_opr(buf2, sizeof(buf2), po, &po->operand[1], 0));
        break;

      case OP_NOT:
        assert_operand_cnt(1);
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        fprintf(fout, "  %s = ~%s;", buf1, buf1);
        break;

      // arithmetic w/flags
      case OP_ADD:
      case OP_SUB:
      case OP_AND:
      case OP_OR:
      case OP_XOR:
      case OP_SHL:
      case OP_SHR:
      dualop_arith:
        assert_operand_cnt(2);
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        fprintf(fout, "  %s %s= %s;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
            op_to_c(po),
            out_src_opr(buf2, sizeof(buf2), po, &po->operand[1], 0));
        last_arith_dst = &po->operand[0];
        delayed_op = NULL;
        break;

      case OP_SAR:
        assert_operand_cnt(2);
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        switch (po->operand[0].lmod) {
        case OPLM_BYTE:
          strcpy(buf3, "(s8)");
          break;
        case OPLM_WORD:
          strcpy(buf3, "(s16)");
          break;
        case OPLM_DWORD:
          strcpy(buf3, "(s32)");
          break;
        default:
          ferr(po, "invalid dst lmod: %d\n", po->operand[0].lmod);
        }
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        fprintf(fout, "  %s = %s%s >> %s;", buf1, buf3, buf1,
            out_src_opr(buf2, sizeof(buf2), po, &po->operand[1], 0));
        last_arith_dst = &po->operand[0];
        delayed_op = NULL;
        break;

      case OP_SBB:
        if (!special_sbb)
          ferr(po, "TODO\n");
        break;

      case OP_INC:
      case OP_DEC:
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        strcpy(buf2, po->op == OP_INC ? "++" : "--");
        switch (po->operand[0].lmod) {
        case OPLM_BYTE:
          fprintf(fout, "  LOBYTE(%s)%s;", buf1, buf2);
          break;
        case OPLM_WORD:
          fprintf(fout, "  LOWORD(%s)%s;", buf1, buf2);
          break;
        case OPLM_DWORD:
          fprintf(fout, "  %s%s;", buf1, buf2);
          break;
        default:
          ferr(po, "invalid dst lmod: %d\n", po->operand[0].lmod);
        }
        last_arith_dst = &po->operand[0];
        delayed_op = NULL;
        break;

      case OP_IMUL:
        if (po->operand_cnt == 2)
          goto dualop_arith;
        ferr(po, "TODO imul\n");
        last_arith_dst = &po->operand[0];
        delayed_op = NULL;
        break;

      case OP_TEST:
      case OP_CMP:
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        delayed_op = po;
        no_output = 1;
        break;

      // note: we reuse OP_Jcc for SETcc, only cls differs
      case OP_JO ... OP_JG:
        if (po->cls == OPC_JCC)
          fprintf(fout, "    goto %s;", po->operand[0].name);
        break;

      case OP_JMP:
        fprintf(fout, "  goto %s;", po->operand[0].name);
        break;

      case OP_CALL:
        pp = po->datap;
        if (pp == NULL)
          ferr(po, "NULL pp\n");

        fprintf(fout, "  ");
        if (!IS(pp->ret_type, "void")) {
          fprintf(fout, "eax = ");
          if (strchr(pp->ret_type, '*'))
            fprintf(fout, "(u32)");
        }
        fprintf(fout, "%s(", opr_name(po, 0));
        for (arg = 0; arg < pp->argc; arg++) {
          if (arg > 0)
            fprintf(fout, ", ");
          if (pp->arg[arg].reg != NULL) {
            fprintf(fout, "%s", pp->arg[arg].reg);
            continue;
          }

          // stack arg
          tmp_op = pp->arg[arg].datap;
          if (tmp_op == NULL)
            ferr(po, "parsed_op missing for arg%d\n", arg);
          fprintf(fout, "%s",
            out_src_opr(buf1, sizeof(buf1), tmp_op, &tmp_op->operand[0], 0));
        }
        fprintf(fout, ");");
        break;

      case OP_RET:
        if (IS(g_func_pp.ret_type, "void"))
          fprintf(fout, "  return;");
        else
          fprintf(fout, "  return eax;");
        break;

      case OP_PUSH:
        ferr(po, "push encountered\n");
        break;

      case OP_POP:
        ferr(po, "pop encountered\n");
        break;

      default:
        no_output = 1;
        ferr(po, "unhandled op type %d, cls %d\n",
          po->op, po->cls);
        break;
    }

    if (g_comment[0] != 0) {
      fprintf(fout, "  // %s", g_comment);
      g_comment[0] = 0;
      no_output = 0;
    }
    if (!no_output)
      fprintf(fout, "\n");
  }

  fprintf(fout, "}\n\n");

  // cleanup
  for (i = 0; i < opcnt; i++) {
    if (ops[i].op == OP_CALL) {
      pp = ops[i].datap;
      if (pp) {
        proto_release(pp);
        free(pp);
      }
    }
  }
  proto_release(&g_func_pp);
}

int main(int argc, char *argv[])
{
  FILE *fout, *fasm, *fhdr;
  char line[256];
  char words[16][256];
  int in_func = 0;
  int eq_alloc;
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

  eq_alloc = 128;
  g_eqs = malloc(eq_alloc * sizeof(g_eqs[0]));
  my_assert_not(g_eqs, NULL);

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
          words[0], g_func);
      strcpy(g_func, words[0]);
      in_func = 1;
      continue;
    }

    if (IS(words[1], "endp")) {
      if (!in_func)
        aerr("endp '%s' while not in_func?\n", words[0]);
      if (!IS(g_func, words[0]))
        aerr("endp '%s' while in_func '%s'?\n",
          words[0], g_func);
      gen_func(fout, fhdr, g_func, pi);
      in_func = 0;
      g_func[0] = 0;
      if (pi != 0) {
        memset(&ops, 0, pi * sizeof(ops[0]));
        memset(g_labels, 0, pi * sizeof(g_labels[0]));
        pi = 0;
      }
      g_eqcnt = 0;
      continue;
    }

    if (IS(words[1], "=")) {
      if (wordc != 5)
        aerr("unhandled equ, wc=%d\n", wordc);
      if (g_eqcnt >= eq_alloc) {
        eq_alloc *= 2;
        g_eqs = realloc(g_eqs, eq_alloc * sizeof(g_eqs[0]));
        my_assert_not(g_eqs, NULL);
      }

      len = strlen(words[0]);
      if (len > sizeof(g_eqs[0].name) - 1)
        aerr("equ name too long: %d\n", len);
      strcpy(g_eqs[g_eqcnt].name, words[0]);

      if (!IS(words[3], "ptr"))
        aerr("unhandled equ\n");
      if (IS(words[2], "dword"))
        g_eqs[g_eqcnt].lmod = OPLM_DWORD;
      else if (IS(words[2], "word"))
        g_eqs[g_eqcnt].lmod = OPLM_WORD;
      else if (IS(words[2], "byte"))
        g_eqs[g_eqcnt].lmod = OPLM_BYTE;
      else
        aerr("bad lmod: '%s'\n", words[2]);

      g_eqs[g_eqcnt].offset = parse_number(words[4]);
      g_eqcnt++;
      continue;
    }

    if (pi >= ARRAY_SIZE(ops))
      aerr("too many ops\n");

    p = strchr(words[0], ':');
    if (p != NULL) {
      len = p - words[0];
      if (len > sizeof(g_labels[0]) - 1)
        aerr("label too long: %d\n", len);
      if (g_labels[pi][0] != 0)
        aerr("dupe label?\n");
      memcpy(g_labels[pi], words[0], len);
      g_labels[pi][len] = 0;
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

// vim:ts=2:shiftwidth=2:expandtab
