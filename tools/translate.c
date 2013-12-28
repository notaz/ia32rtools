#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "my_assert.h"
#include "my_str.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define IS(w, y) !strcmp(w, y)
#define IS_START(w, y) !strncmp(w, y, strlen(y))

#include "protoparse.h"

static const char *asmfn;
static int asmln;
static FILE *g_fhdr;

#define anote(fmt, ...) \
	printf("%s:%d: note: " fmt, asmfn, asmln, ##__VA_ARGS__)
#define awarn(fmt, ...) \
	printf("%s:%d: warning: " fmt, asmfn, asmln, ##__VA_ARGS__)
#define aerr(fmt, ...) do { \
	printf("%s:%d: error: " fmt, asmfn, asmln, ##__VA_ARGS__); \
  fcloseall(); \
	exit(1); \
} while (0)

enum op_flags {
  OPF_RMD    = (1 << 0), /* removed or optimized out */
  OPF_DATA   = (1 << 1), /* data processing - writes to dst opr */
  OPF_FLAGS  = (1 << 2), /* sets flags */
  OPF_JMP    = (1 << 3), /* branches, ret and call */
  OPF_CC     = (1 << 4), /* uses flags */
  OPF_TAIL   = (1 << 5), /* ret or tail call */
  OPF_RSAVE  = (1 << 6), /* push/pop is local reg save/load */
  OPF_REP    = (1 << 7), /* prefixed by rep */
  OPF_REPZ   = (1 << 8), /* rep is repe/repz */
  OPF_REPNZ  = (1 << 9), /* rep is repne/repnz */
};

enum op_op {
	OP_INVAL,
	OP_NOP,
	OP_PUSH,
	OP_POP,
	OP_MOV,
	OP_LEA,
	OP_MOVZX,
	OP_MOVSX,
	OP_NOT,
	OP_CDQ,
	OP_STOS,
	OP_MOVS,
	OP_CMPS,
	OP_RET,
	OP_ADD,
	OP_SUB,
	OP_AND,
	OP_OR,
	OP_XOR,
	OP_SHL,
	OP_SHR,
	OP_SAR,
	OP_ROL,
	OP_ROR,
	OP_ADC,
	OP_SBB,
	OP_INC,
	OP_DEC,
	OP_NEG,
	OP_MUL,
	OP_IMUL,
	OP_DIV,
	OP_IDIV,
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
  unsigned int is_ptr:1;   // pointer in C
  unsigned int is_array:1; // array in C
  int reg;
  unsigned int val;
  char name[256];
};

struct parsed_op {
  enum op_op op;
  struct parsed_opr operand[MAX_OPERANDS];
  unsigned int flags;
  int operand_cnt;
  int regmask_src;        // all referensed regs
  int regmask_dst;
  int pfomask;            // flagop: parsed_flag_op that can't be delayed
  int argmask;            // push: args that are altered before call
  int cc_scratch;         // scratch storage during analysis
  int bt_i;               // branch target for branches
  struct parsed_data *btj;// branch targets for jumptables
  void *datap;
};

// datap:
// OP_CALL - ptr to parsed_proto
// (OPF_CC) - point to corresponding (OPF_FLAGS)

struct parsed_equ {
  char name[64];
  enum opr_lenmod lmod;
  int offset;
};

struct parsed_data {
  char label[256];
  enum opr_type type;
  enum opr_lenmod lmod;
  int count;
  int count_alloc;
  struct {
    union {
      char *label;
      unsigned int val;
    } u;
    int bt_i;
  } *d;
};

struct label_ref {
  int i;
  struct label_ref *next;
};

enum ida_func_attr {
  IDAFA_BP_FRAME = (1 << 0),
  IDAFA_LIB_FUNC = (1 << 1),
  IDAFA_STATIC   = (1 << 2),
  IDAFA_NORETURN = (1 << 3),
  IDAFA_THUNK    = (1 << 4),
  IDAFA_FPD      = (1 << 5),
};

#define MAX_OPS 4096

static struct parsed_op ops[MAX_OPS];
static struct parsed_equ *g_eqs;
static int g_eqcnt;
static char g_labels[MAX_OPS][32];
static struct label_ref g_label_refs[MAX_OPS];
static struct parsed_proto g_func_pp;
static struct parsed_data *g_func_pd;
static int g_func_pd_cnt;
static char g_func[256];
static char g_comment[256];
static int g_bp_frame;
static int g_sp_frame;
static int g_stack_fsz;
static int g_ida_func_attr;
#define ferr(op_, fmt, ...) do { \
  printf("error:%s:#%zd: '%s': " fmt, g_func, (op_) - ops, \
    dump_op(op_), ##__VA_ARGS__); \
  fcloseall(); \
  exit(1); \
} while (0)

#define MAX_REGS 8

const char *regs_r32[] = { "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp" };
const char *regs_r16[] = { "ax", "bx", "cx", "dx", "si", "di", "bp", "sp" };
const char *regs_r8l[] = { "al", "bl", "cl", "dl" };
const char *regs_r8h[] = { "ah", "bh", "ch", "dh" };

enum x86_regs { xUNSPEC = -1, xAX, xBX, xCX, xDX, xSI, xDI, xBP, xSP };

// possible basic comparison types (without inversion)
enum parsed_flag_op {
  PFO_O,  // 0 OF=1
  PFO_C,  // 2 CF=1
  PFO_Z,  // 4 ZF=1
  PFO_BE, // 6 CF=1||ZF=1
  PFO_S,  // 8 SF=1
  PFO_P,  // a PF=1
  PFO_L,  // c SF!=OF
  PFO_LE, // e ZF=1||SF!=OF
};

static const char *parsed_flag_op_names[] = {
  "o", "c", "z", "be", "s", "p", "l", "le"
};

static int char_array_i(const char *array[], size_t len, const char *s)
{
  int i;

  for (i = 0; i < len; i++)
    if (IS(s, array[i]))
      return i;

  return -1;
}

static void printf_number(char *buf, size_t buf_size,
  unsigned long number)
{
  // output in C-friendly form
  snprintf(buf, buf_size, number < 10 ? "%lu" : "0x%02lx", number);
}

static int parse_reg(enum opr_lenmod *reg_lmod, const char *s)
{
  int reg;

  reg = char_array_i(regs_r32, ARRAY_SIZE(regs_r32), s);
  if (reg >= 0) {
    *reg_lmod = OPLM_DWORD;
    return reg;
  }
  reg = char_array_i(regs_r16, ARRAY_SIZE(regs_r16), s);
  if (reg >= 0) {
    *reg_lmod = OPLM_WORD;
    return reg;
  }
  reg = char_array_i(regs_r8h, ARRAY_SIZE(regs_r8h), s);
  if (reg >= 0) {
    *reg_lmod = OPLM_BYTE;
    return reg;
  }
  reg = char_array_i(regs_r8l, ARRAY_SIZE(regs_r8l), s);
  if (reg >= 0) {
    *reg_lmod = OPLM_BYTE;
    return reg;
  }

  return -1;
}

static unsigned long parse_number(const char *number)
{
  int len = strlen(number);
  const char *p = number;
  char *endp = NULL;
  unsigned long ret;
  int neg = 0;
  int bad;

  if (*p == '-') {
    neg = 1;
    p++;
  }
  if (len > 1 && *p == '0')
    p++;
  if (number[len - 1] == 'h') {
    ret = strtoul(p, &endp, 16);
    bad = (*endp != 'h');
  }
  else {
    ret = strtoul(p, &endp, 10);
    bad = (*endp != 0);
  }
  if (bad)
    aerr("number parsing failed\n");
  if (neg)
    ret = -ret;
  return ret;
}

static int parse_indmode(char *name, int *regmask, int need_c_cvt)
{
  enum opr_lenmod lmod;
  char cvtbuf[256];
  char *d = cvtbuf;
  char *s = name;
  char w[64];
  long number;
  int reg;
  int c = 0;

  *d = 0;

  while (*s != 0) {
    d += strlen(d);
    while (my_isblank(*s))
      s++;
    for (; my_issep(*s); d++, s++)
      *d = *s;
    while (my_isblank(*s))
      s++;
    *d = 0;

    // skip 'ds:' prefix
    if (IS_START(s, "ds:"))
      s += 3;

    s = next_idt(w, sizeof(w), s);
    if (w[0] == 0)
      break;
    c++;

    reg = parse_reg(&lmod, w);
    if (reg >= 0) {
      *regmask |= 1 << reg;
      goto pass;
    }

    if ('0' <= w[0] && w[0] <= '9') {
      number = parse_number(w);
      printf_number(d, sizeof(cvtbuf) - (d - cvtbuf), number);
      continue;
    }

    // probably some label/identifier - pass

pass:
    snprintf(d, sizeof(cvtbuf) - (d - cvtbuf), "%s", w);
  }

  if (need_c_cvt)
    strcpy(name, cvtbuf);

  return c;
}

static int is_reg_in_str(const char *s)
{
  int i;

  if (strlen(s) < 3 || (s[3] && !my_issep(s[3]) && !my_isblank(s[3])))
    return 0;

  for (i = 0; i < ARRAY_SIZE(regs_r32); i++)
    if (!strncmp(s, regs_r32[i], 3))
      return 1;

  return 0;
}

static const char *parse_stack_el(const char *name, char *extra_reg)
{
  const char *p, *p2, *s;
  char *endp = NULL;
  char buf[32];
  long val;
  int len;

  p = name;
  if (IS_START(p + 3, "+ebp+") && is_reg_in_str(p)) {
    p += 4;
    if (extra_reg != NULL) {
      strncpy(extra_reg, name, 3);
      extra_reg[4] = 0;
    }
  }

  if (IS_START(p, "ebp+")) {
    p += 4;

    p2 = strchr(p, '+');
    if (p2 != NULL && is_reg_in_str(p)) {
      if (extra_reg != NULL) {
        strncpy(extra_reg, p, p2 - p);
        extra_reg[p2 - p] = 0;
      }
      p = p2 + 1;
    }

    if (!('0' <= *p && *p <= '9'))
      return p;

    return NULL;
  }

  if (!IS_START(name, "esp+"))
    return NULL;

  p = strchr(name + 4, '+');
  if (p) {
    // must be a number after esp+, already converted to 0x..
    s = name + 4;
    if (!('0' <= *s && *s <= '9')) {
		  aerr("%s nan?\n", __func__);
      return NULL;
    }
    if (s[0] == '0' && s[1] == 'x')
      s += 2;
    len = p - s;
    if (len < sizeof(buf) - 1) {
      strncpy(buf, s, len);
      buf[len] = 0;
      val = strtol(buf, &endp, 16);
      if (val == 0 || *endp != 0) {
        aerr("%s num parse fail for '%s'\n", __func__, buf);
        return NULL;
      }
    }
    p++;
  }
  else
    p = name + 4;

  if ('0' <= *p && *p <= '9')
    return NULL;

  return p;
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

static int guess_lmod_from_c_type(enum opr_lenmod *lmod,
  const struct parsed_type *c_type)
{
  static const char *dword_types[] = {
    "int", "_DWORD", "DWORD", "HANDLE", "HWND", "HMODULE",
  };
  static const char *word_types[] = {
    "__int16", "unsigned __int16",
  };
  static const char *byte_types[] = {
    "char", "__int8", "unsigned __int8", "BYTE",
  };
  const char *n;
  int i;

  if (c_type->is_ptr) {
    *lmod = OPLM_DWORD;
    return 1;
  }

  n = skip_type_mod(c_type->name);

  for (i = 0; i < ARRAY_SIZE(dword_types); i++) {
    if (IS(n, dword_types[i])) {
      *lmod = OPLM_DWORD;
      return 1;
    }
  }

  for (i = 0; i < ARRAY_SIZE(word_types); i++) {
    if (IS(n, word_types[i])) {
      *lmod = OPLM_WORD;
      return 1;
    }
  }

  for (i = 0; i < ARRAY_SIZE(byte_types); i++) {
    if (IS(n, byte_types[i])) {
      *lmod = OPLM_BYTE;
      return 1;
    }
  }

  return 0;
}

static enum opr_type lmod_from_directive(const char *d)
{
  if (IS(d, "dd"))
    return OPLM_DWORD;
  else if (IS(d, "dw"))
    return OPLM_WORD;
  else if (IS(d, "db"))
    return OPLM_BYTE;

  aerr("unhandled directive: '%s'\n", d);
  return OPLM_UNSPEC;
}

static void setup_reg_opr(struct parsed_opr *opr, int reg, enum opr_lenmod lmod,
  int *regmask)
{
  opr->type = OPT_REG;
  opr->reg = reg;
  opr->lmod = lmod;
  *regmask |= 1 << reg;
}

static struct parsed_equ *equ_find(struct parsed_op *po, const char *name,
  int *extra_offs);

static int parse_operand(struct parsed_opr *opr,
  int *regmask, int *regmask_indirect,
  char words[16][256], int wordc, int w, unsigned int op_flags)
{
  struct parsed_proto pp;
  enum opr_lenmod tmplmod;
  unsigned long number;
  int ret, len;
  int wordc_in;
  char *tmp;
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

  wordc_in = wordc - w;

  if ((op_flags & OPF_JMP) && wordc_in > 0
      && !('0' <= words[w][0] && words[w][0] <= '9'))
  {
    const char *label = NULL;

    if (wordc_in == 3 && !strncmp(words[w], "near", 4)
     && IS(words[w + 1], "ptr"))
      label = words[w + 2];
    else if (wordc_in == 2 && IS(words[w], "short"))
      label = words[w + 1];
    else if (wordc_in == 1
          && strchr(words[w], '[') == NULL
          && parse_reg(&tmplmod, words[w]) < 0)
      label = words[w];

    if (label != NULL) {
      opr->type = OPT_LABEL;
      if (IS_START(label, "ds:"))
        label += 3;
      strcpy(opr->name, label);
      return wordc;
    }
  }

  if (wordc_in >= 3) {
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
      wordc_in = wordc - w;
    }
  }

  if (wordc_in == 2) {
    if (IS(words[w], "offset")) {
      opr->type = OPT_OFFSET;
      strcpy(opr->name, words[w + 1]);
      return wordc;
    }
    if (IS(words[w], "(offset")) {
      char *p = strchr(words[w + 1], ')');
      if (p == NULL)
        aerr("parse of bracketed offset failed\n");
      *p = 0;
      opr->type = OPT_OFFSET;
      strcpy(opr->name, words[w + 1]);
      return wordc;
    }
  }

  if (wordc_in != 1)
    aerr("parse_operand 1 word expected\n");

  tmp = words[w];
  if (IS_START(tmp, "ds:"))
    tmp += 3;
  strcpy(opr->name, tmp);

  if (words[w][0] == '[') {
    opr->type = OPT_REGMEM;
    ret = sscanf(words[w], "[%[^]]]", opr->name);
    if (ret != 1)
      aerr("[] parse failure\n");

    parse_indmode(opr->name, regmask_indirect, 1);
    if (opr->lmod == OPLM_UNSPEC && parse_stack_el(opr->name, NULL)) {
      // might be an equ
      struct parsed_equ *eq =
        equ_find(NULL, parse_stack_el(opr->name, NULL), &i);
      if (eq)
        opr->lmod = eq->lmod;
    }
    return wordc;
  }
  else if (strchr(words[w], '[')) {
    // label[reg] form
    opr->type = OPT_REGMEM;
    if (opr->lmod == OPLM_UNSPEC)
      guess_lmod_from_name(opr);
    parse_indmode(strchr(words[w], '['), regmask_indirect, 0);
    return wordc;
  }
  else if (('0' <= words[w][0] && words[w][0] <= '9')
    || words[w][0] == '-')
  {
    number = parse_number(words[w]);
    opr->type = OPT_CONST;
    opr->val = number;
    printf_number(opr->name, sizeof(opr->name), number);
    return wordc;
  }

  ret = parse_reg(&tmplmod, opr->name);
  if (ret >= 0) {
    setup_reg_opr(opr, ret, tmplmod, regmask);
    return wordc;
  }

  // most likely var in data segment
  opr->type = OPT_LABEL;

  ret = proto_parse(g_fhdr, opr->name, &pp);
  if (ret == 0) {
    if (pp.is_fptr) {
      opr->lmod = OPLM_DWORD;
      opr->is_ptr = 1;
    }
    else if (opr->lmod == OPLM_UNSPEC) {
      if (!guess_lmod_from_c_type(&opr->lmod, &pp.type))
        anote("unhandled C type '%s' for '%s'\n", pp.type.name, opr->name);
    }
    opr->is_ptr = pp.type.is_ptr;
    opr->is_array = pp.type.is_array;
  }
  proto_release(&pp);

  if (opr->lmod == OPLM_UNSPEC)
    guess_lmod_from_name(opr);
  return wordc;
}

static const struct {
  const char *name;
  unsigned int flags;
} pref_table[] = {
  { "rep",    OPF_REP },
  { "repe",   OPF_REP|OPF_REPZ },
  { "repz",   OPF_REP|OPF_REPZ },
  { "repne",  OPF_REP|OPF_REPNZ },
  { "repnz",  OPF_REP|OPF_REPNZ },
};

static const struct {
  const char *name;
  enum op_op op;
  unsigned int minopr;
  unsigned int maxopr;
  unsigned int flags;
} op_table[] = {
  { "nop",  OP_NOP,    0, 0, 0 },
  { "push", OP_PUSH,   1, 1, 0 },
  { "pop",  OP_POP,    1, 1, OPF_DATA },
  { "mov" , OP_MOV,    2, 2, OPF_DATA },
  { "lea",  OP_LEA,    2, 2, OPF_DATA },
  { "movzx",OP_MOVZX,  2, 2, OPF_DATA },
  { "movsx",OP_MOVSX,  2, 2, OPF_DATA },
  { "not",  OP_NOT,    1, 1, OPF_DATA },
  { "cdq",  OP_CDQ,    0, 0, OPF_DATA },
  { "stosb",OP_STOS,   0, 0, OPF_DATA },
  { "stosw",OP_STOS,   0, 0, OPF_DATA },
  { "stosd",OP_STOS,   0, 0, OPF_DATA },
  { "movsb",OP_MOVS,   0, 0, OPF_DATA },
  { "movsw",OP_MOVS,   0, 0, OPF_DATA },
  { "movsd",OP_MOVS,   0, 0, OPF_DATA },
  { "cmpsb",OP_CMPS,   0, 0, OPF_DATA|OPF_FLAGS },
  { "cmpsw",OP_CMPS,   0, 0, OPF_DATA|OPF_FLAGS },
  { "cmpsd",OP_CMPS,   0, 0, OPF_DATA|OPF_FLAGS },
  { "add",  OP_ADD,    2, 2, OPF_DATA|OPF_FLAGS },
  { "sub",  OP_SUB,    2, 2, OPF_DATA|OPF_FLAGS },
  { "and",  OP_AND,    2, 2, OPF_DATA|OPF_FLAGS },
  { "or",   OP_OR,     2, 2, OPF_DATA|OPF_FLAGS },
  { "xor",  OP_XOR,    2, 2, OPF_DATA|OPF_FLAGS },
  { "shl",  OP_SHL,    2, 2, OPF_DATA|OPF_FLAGS },
  { "shr",  OP_SHR,    2, 2, OPF_DATA|OPF_FLAGS },
  { "sal",  OP_SHL,    2, 2, OPF_DATA|OPF_FLAGS },
  { "sar",  OP_SAR,    2, 2, OPF_DATA|OPF_FLAGS },
  { "rol",  OP_ROL,    2, 2, OPF_DATA|OPF_FLAGS },
  { "ror",  OP_ROR,    2, 2, OPF_DATA|OPF_FLAGS },
  { "adc",  OP_ADC,    2, 2, OPF_DATA|OPF_FLAGS|OPF_CC },
  { "sbb",  OP_SBB,    2, 2, OPF_DATA|OPF_FLAGS|OPF_CC },
  { "inc",  OP_INC,    1, 1, OPF_DATA|OPF_FLAGS },
  { "dec",  OP_DEC,    1, 1, OPF_DATA|OPF_FLAGS },
  { "neg",  OP_NEG,    1, 1, OPF_DATA|OPF_FLAGS },
  { "mul",  OP_MUL,    1, 1, OPF_DATA|OPF_FLAGS },
  { "imul", OP_IMUL,   1, 3, OPF_DATA|OPF_FLAGS },
  { "div",  OP_DIV,    1, 1, OPF_DATA|OPF_FLAGS },
  { "idiv", OP_IDIV,   1, 1, OPF_DATA|OPF_FLAGS },
  { "test", OP_TEST,   2, 2, OPF_FLAGS },
  { "cmp",  OP_CMP,    2, 2, OPF_FLAGS },
  { "retn", OP_RET,    0, 1, OPF_JMP|OPF_TAIL },
  { "call", OP_CALL,   1, 1, OPF_JMP|OPF_FLAGS },
  { "jmp",  OP_JMP,    1, 1, OPF_JMP },
  { "jo",   OP_JO,     1, 1, OPF_JMP|OPF_CC }, // 70 OF=1
  { "jno",  OP_JNO,    1, 1, OPF_JMP|OPF_CC }, // 71 OF=0
  { "jc",   OP_JC,     1, 1, OPF_JMP|OPF_CC }, // 72 CF=1
  { "jb",   OP_JC,     1, 1, OPF_JMP|OPF_CC }, // 72
  { "jnc",  OP_JNC,    1, 1, OPF_JMP|OPF_CC }, // 73 CF=0
  { "jnb",  OP_JNC,    1, 1, OPF_JMP|OPF_CC }, // 73
  { "jae",  OP_JNC,    1, 1, OPF_JMP|OPF_CC }, // 73
  { "jz",   OP_JZ,     1, 1, OPF_JMP|OPF_CC }, // 74 ZF=1
  { "je",   OP_JZ,     1, 1, OPF_JMP|OPF_CC }, // 74
  { "jnz",  OP_JNZ,    1, 1, OPF_JMP|OPF_CC }, // 75 ZF=0
  { "jne",  OP_JNZ,    1, 1, OPF_JMP|OPF_CC }, // 75
  { "jbe",  OP_JBE,    1, 1, OPF_JMP|OPF_CC }, // 76 CF=1 || ZF=1
  { "jna",  OP_JBE,    1, 1, OPF_JMP|OPF_CC }, // 76
  { "ja",   OP_JA,     1, 1, OPF_JMP|OPF_CC }, // 77 CF=0 && ZF=0
  { "jnbe", OP_JA,     1, 1, OPF_JMP|OPF_CC }, // 77
  { "js",   OP_JS,     1, 1, OPF_JMP|OPF_CC }, // 78 SF=1
  { "jns",  OP_JNS,    1, 1, OPF_JMP|OPF_CC }, // 79 SF=0
  { "jp",   OP_JP,     1, 1, OPF_JMP|OPF_CC }, // 7a PF=1
  { "jpe",  OP_JP,     1, 1, OPF_JMP|OPF_CC }, // 7a
  { "jnp",  OP_JNP,    1, 1, OPF_JMP|OPF_CC }, // 7b PF=0
  { "jpo",  OP_JNP,    1, 1, OPF_JMP|OPF_CC }, // 7b
  { "jl",   OP_JL,     1, 1, OPF_JMP|OPF_CC }, // 7c SF!=OF
  { "jnge", OP_JL,     1, 1, OPF_JMP|OPF_CC }, // 7c
  { "jge",  OP_JGE,    1, 1, OPF_JMP|OPF_CC }, // 7d SF=OF
  { "jnl",  OP_JGE,    1, 1, OPF_JMP|OPF_CC }, // 7d
  { "jle",  OP_JLE,    1, 1, OPF_JMP|OPF_CC }, // 7e ZF=1 || SF!=OF
  { "jng",  OP_JLE,    1, 1, OPF_JMP|OPF_CC }, // 7e
  { "jg",   OP_JG,     1, 1, OPF_JMP|OPF_CC }, // 7f ZF=0 && SF=OF
  { "jnle", OP_JG,     1, 1, OPF_JMP|OPF_CC }, // 7f
  { "seto",   OP_JO,   1, 1, OPF_DATA|OPF_CC },
  { "setno",  OP_JNO,  1, 1, OPF_DATA|OPF_CC },
  { "setc",   OP_JC,   1, 1, OPF_DATA|OPF_CC },
  { "setb",   OP_JC,   1, 1, OPF_DATA|OPF_CC },
  { "setnc",  OP_JNC,  1, 1, OPF_DATA|OPF_CC },
  { "setae",  OP_JNC,  1, 1, OPF_DATA|OPF_CC },
  { "setz",   OP_JZ,   1, 1, OPF_DATA|OPF_CC },
  { "sete",   OP_JZ,   1, 1, OPF_DATA|OPF_CC },
  { "setnz",  OP_JNZ,  1, 1, OPF_DATA|OPF_CC },
  { "setne",  OP_JNZ,  1, 1, OPF_DATA|OPF_CC },
  { "setbe",  OP_JBE,  1, 1, OPF_DATA|OPF_CC },
  { "setna",  OP_JBE,  1, 1, OPF_DATA|OPF_CC },
  { "seta",   OP_JA,   1, 1, OPF_DATA|OPF_CC },
  { "setnbe", OP_JA,   1, 1, OPF_DATA|OPF_CC },
  { "sets",   OP_JS,   1, 1, OPF_DATA|OPF_CC },
  { "setns",  OP_JNS,  1, 1, OPF_DATA|OPF_CC },
  { "setp",   OP_JP,   1, 1, OPF_DATA|OPF_CC },
  { "setpe",  OP_JP,   1, 1, OPF_DATA|OPF_CC },
  { "setnp",  OP_JNP,  1, 1, OPF_DATA|OPF_CC },
  { "setpo",  OP_JNP,  1, 1, OPF_DATA|OPF_CC },
  { "setl",   OP_JL,   1, 1, OPF_DATA|OPF_CC },
  { "setnge", OP_JL,   1, 1, OPF_DATA|OPF_CC },
  { "setge",  OP_JGE,  1, 1, OPF_DATA|OPF_CC },
  { "setnl",  OP_JGE,  1, 1, OPF_DATA|OPF_CC },
  { "setle",  OP_JLE,  1, 1, OPF_DATA|OPF_CC },
  { "setng",  OP_JLE,  1, 1, OPF_DATA|OPF_CC },
  { "setg",   OP_JG,   1, 1, OPF_DATA|OPF_CC },
  { "setnle", OP_JG,   1, 1, OPF_DATA|OPF_CC },
};

static void parse_op(struct parsed_op *op, char words[16][256], int wordc)
{
  enum opr_lenmod lmod = OPLM_UNSPEC;
  int prefix_flags = 0;
  int regmask_ind;
  int regmask;
  int op_w = 0;
  int opr = 0;
  int w = 0;
  int i;

  for (i = 0; i < ARRAY_SIZE(pref_table); i++) {
    if (IS(words[w], pref_table[i].name)) {
      prefix_flags = pref_table[i].flags;
      break;
    }
  }

  if (prefix_flags) {
    if (wordc <= 1)
      aerr("lone prefix: '%s'\n", words[0]);
    w++;
  }

  op_w = w;
  for (i = 0; i < ARRAY_SIZE(op_table); i++) {
    if (IS(words[w], op_table[i].name))
      break;
  }

  if (i == ARRAY_SIZE(op_table))
    aerr("unhandled op: '%s'\n", words[0]);
  w++;

  op->op = op_table[i].op;
  op->flags = op_table[i].flags | prefix_flags;
  op->regmask_src = op->regmask_dst = 0;

  for (opr = 0; opr < op_table[i].minopr; opr++) {
    regmask = regmask_ind = 0;
    w = parse_operand(&op->operand[opr], &regmask, &regmask_ind,
      words, wordc, w, op->flags);

    if (opr == 0 && (op->flags & OPF_DATA))
      op->regmask_dst = regmask;
    // for now, mark dst as src too
    op->regmask_src |= regmask | regmask_ind;
  }

  for (; w < wordc && opr < op_table[i].maxopr; opr++) {
    w = parse_operand(&op->operand[opr],
      &op->regmask_src, &op->regmask_src,
      words, wordc, w, op->flags);
  }

  if (w < wordc)
    aerr("parse_op %s incomplete: %d/%d\n",
      words[0], w, wordc);

  // special cases
  op->operand_cnt = opr;
  if (!strncmp(op_table[i].name, "set", 3))
    op->operand[0].lmod = OPLM_BYTE;

  // ops with implicit argumets
  switch (op->op) {
  case OP_CDQ:
    op->operand_cnt = 2;
    setup_reg_opr(&op->operand[0], xDX, OPLM_DWORD, &op->regmask_dst);
    setup_reg_opr(&op->operand[1], xAX, OPLM_DWORD, &op->regmask_src);
    break;

  case OP_STOS:
    if (op->operand_cnt != 0)
      break;
    if      (IS(words[op_w], "stosb"))
      lmod = OPLM_BYTE;
    else if (IS(words[op_w], "stosw"))
      lmod = OPLM_WORD;
    else if (IS(words[op_w], "stosd"))
      lmod = OPLM_DWORD;
    op->operand_cnt = 3;
    setup_reg_opr(&op->operand[0], xDI, lmod, &op->regmask_src);
    setup_reg_opr(&op->operand[1], xCX, OPLM_DWORD, &op->regmask_src);
    op->regmask_dst = op->regmask_src;
    setup_reg_opr(&op->operand[2], xAX, OPLM_DWORD, &op->regmask_src);
    break;

  case OP_MOVS:
  case OP_CMPS:
    if (op->operand_cnt != 0)
      break;
    if      (words[op_w][4] == 'b')
      lmod = OPLM_BYTE;
    else if (words[op_w][4] == 'w')
      lmod = OPLM_WORD;
    else if (words[op_w][4] == 'd')
      lmod = OPLM_DWORD;
    op->operand_cnt = 3;
    setup_reg_opr(&op->operand[0], xDI, lmod, &op->regmask_src);
    setup_reg_opr(&op->operand[1], xSI, OPLM_DWORD, &op->regmask_src);
    setup_reg_opr(&op->operand[2], xCX, OPLM_DWORD, &op->regmask_src);
    op->regmask_dst = op->regmask_src;
    break;

  case OP_IMUL:
    if (op->operand_cnt != 1)
      break;
    // fallthrough
  case OP_MUL:
    // singleop mul
    op->regmask_dst = (1 << xDX) | (1 << xAX);
    op->regmask_src |= (1 << xAX);
    if (op->operand[0].lmod == OPLM_UNSPEC)
      op->operand[0].lmod = OPLM_DWORD;
    break;

  case OP_DIV:
  case OP_IDIV:
    // we could set up operands for edx:eax, but there is no real need to
    // (see is_opr_modified())
    regmask = (1 << xDX) | (1 << xAX);
    op->regmask_dst = regmask;
    op->regmask_src |= regmask;
    if (op->operand[0].lmod == OPLM_UNSPEC)
      op->operand[0].lmod = OPLM_DWORD;
    break;

  case OP_SHL:
  case OP_SHR:
  case OP_SAR:
  case OP_ROL:
  case OP_ROR:
    if (op->operand[1].lmod == OPLM_UNSPEC)
      op->operand[1].lmod = OPLM_BYTE;
    break;

  case OP_PUSH:
    if (op->operand[0].lmod == OPLM_UNSPEC
        && (op->operand[0].type == OPT_CONST
         || op->operand[0].type == OPT_OFFSET
         || op->operand[0].type == OPT_LABEL))
      op->operand[0].lmod = OPLM_DWORD;
    break;

  // alignment
  case OP_MOV:
    if (op->operand[0].type == OPT_REG && op->operand[1].type == OPT_REG
     && op->operand[0].reg == xDI && op->operand[1].reg == xDI)
    {
      op->flags |= OPF_RMD;
    }
    break;

  default:
    break;
  }
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

  if (po == NULL)
    return "???";

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

static const char *lmod_type_u(struct parsed_op *po,
  enum opr_lenmod lmod)
{
  switch (lmod) {
  case OPLM_DWORD:
    return "u32";
  case OPLM_WORD:
    return "u16";
  case OPLM_BYTE:
    return "u8";
  default:
    ferr(po, "invalid lmod: %d\n", lmod);
    return "(_invalid_)";
  }
}

static const char *lmod_cast_u(struct parsed_op *po,
  enum opr_lenmod lmod)
{
  switch (lmod) {
  case OPLM_DWORD:
    return "";
  case OPLM_WORD:
    return "(u16)";
  case OPLM_BYTE:
    return "(u8)";
  default:
    ferr(po, "invalid lmod: %d\n", lmod);
    return "(_invalid_)";
  }
}

static const char *lmod_cast_u_ptr(struct parsed_op *po,
  enum opr_lenmod lmod)
{
  switch (lmod) {
  case OPLM_DWORD:
    return "*(u32 *)";
  case OPLM_WORD:
    return "*(u16 *)";
  case OPLM_BYTE:
    return "*(u8 *)";
  default:
    ferr(po, "invalid lmod: %d\n", lmod);
    return "(_invalid_)";
  }
}

static const char *lmod_cast_s(struct parsed_op *po,
  enum opr_lenmod lmod)
{
  switch (lmod) {
  case OPLM_DWORD:
    return "(s32)";
  case OPLM_WORD:
    return "(s16)";
  case OPLM_BYTE:
    return "(s8)";
  default:
    ferr(po, "%s: invalid lmod: %d\n", __func__, lmod);
    return "(_invalid_)";
  }
}

static const char *lmod_cast(struct parsed_op *po,
  enum opr_lenmod lmod, int is_signed)
{
  return is_signed ?
    lmod_cast_s(po, lmod) :
    lmod_cast_u(po, lmod);
}

static int lmod_bytes(struct parsed_op *po, enum opr_lenmod lmod)
{
  switch (lmod) {
  case OPLM_DWORD:
    return 4;
  case OPLM_WORD:
    return 2;
  case OPLM_BYTE:
    return 1;
  default:
    ferr(po, "%s: invalid lmod: %d\n", __func__, lmod);
    return 0;
  }
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

static struct parsed_equ *equ_find(struct parsed_op *po, const char *name,
  int *extra_offs)
{
  const char *p;
  char *endp;
  int namelen;
  int i;

  *extra_offs = 0;
  namelen = strlen(name);

  p = strchr(name, '+');
  if (p != NULL) {
    namelen = p - name;
    if (namelen <= 0)
      ferr(po, "equ parse failed for '%s'\n", name);

    if (IS_START(p, "0x"))
      p += 2;
    *extra_offs = strtol(p, &endp, 16);
    if (*endp != 0)
      ferr(po, "equ parse failed for '%s'\n", name);
  }

  for (i = 0; i < g_eqcnt; i++)
    if (strncmp(g_eqs[i].name, name, namelen) == 0
     && g_eqs[i].name[namelen] == 0)
      break;
  if (i >= g_eqcnt) {
    if (po != NULL)
      ferr(po, "unresolved equ name: '%s'\n", name);
    return NULL;
  }

  return &g_eqs[i];
}

static void stack_frame_access(struct parsed_op *po,
  enum opr_lenmod lmod, char *buf, size_t buf_size,
  const char *name, const char *cast, int is_src, int is_lea)
{
  enum opr_lenmod tmp_lmod = OPLM_UNSPEC;
  const char *prefix = "";
  const char *bp_arg = NULL;
  char ofs_reg[16] = { 0, };
  struct parsed_equ *eq;
  const char *p;
  char *endp = NULL;
  int i, arg_i, arg_s;
  int stack_ra = 0;
  int offset = 0;
  int sf_ofs;

  if (!IS_START(name, "ebp-")) {
    bp_arg = parse_stack_el(name, ofs_reg);
    snprintf(g_comment, sizeof(g_comment), "%s", bp_arg);
    eq = equ_find(po, bp_arg, &offset);
    if (eq == NULL)
      ferr(po, "detected but missing eq\n");
    offset += eq->offset;
  }
  else {
    p = name + 4;
    if (IS_START(p, "0x"))
      p += 2;
    offset = -strtoul(p, &endp, 16);
    if (*endp != 0)
      ferr(po, "ebp- parse of '%s' failed\n", name);
  }

  if (!strncmp(name, "ebp", 3))
    stack_ra = 4;

  if (stack_ra <= offset && offset < stack_ra + 4)
    ferr(po, "reference to ra? %d %d\n", offset, stack_ra);

  if (offset > stack_ra)
  {
    arg_i = (offset - stack_ra - 4) / 4;
    if (arg_i < 0 || arg_i >= g_func_pp.argc_stack)
    {
      if (g_func_pp.is_vararg && arg_i == g_func_pp.argc_stack && is_lea) {
        // should be va_list
        if (cast[0] == 0)
          cast = "(u32)";
        snprintf(buf, buf_size, "%sap", cast);
        return;
      }
      ferr(po, "offset %d (%s,%d) doesn't map to any arg\n",
        offset, bp_arg, arg_i);
    }
    if (ofs_reg[0] != 0)
      ferr(po, "offset reg on arg access?\n");

    for (i = arg_s = 0; i < g_func_pp.argc; i++) {
      if (g_func_pp.arg[i].reg != NULL)
        continue;
      if (arg_s == arg_i)
        break;
      arg_s++;
    }
    if (i == g_func_pp.argc)
      ferr(po, "arg %d not in prototype?\n", arg_i);

    switch (lmod)
    {
    case OPLM_BYTE:
      if (is_lea)
        ferr(po, "lea/byte to arg?\n");
      if (is_src && (offset & 3) == 0)
        snprintf(buf, buf_size, "(u8)a%d", i + 1);
      else
        snprintf(buf, buf_size, "BYTE%d(a%d)", offset & 3, i + 1);
      break;

    case OPLM_WORD:
      if (is_lea)
        ferr(po, "lea/word to arg?\n");
      if (offset & 1)
        ferr(po, "unaligned arg access\n");
      if (is_src && (offset & 2) == 0)
        snprintf(buf, buf_size, "(u16)a%d", i + 1);
      else
        snprintf(buf, buf_size, "%sWORD(a%d)",
          (offset & 2) ? "HI" : "LO", i + 1);
      break;

    case OPLM_DWORD:
      if (offset & 3)
        ferr(po, "unaligned arg access\n");
      if (cast[0])
        prefix = cast;
      else if (is_src)
        prefix = "(u32)";
      snprintf(buf, buf_size, "%s%sa%d", prefix, is_lea ? "&" : "", i + 1);
      break;

    default:
      ferr(po, "bp_arg bad lmod: %d\n", lmod);
    }

    // common problem
    guess_lmod_from_c_type(&tmp_lmod, &g_func_pp.arg[i].type);
    if ((offset & 3) && tmp_lmod != OPLM_DWORD)
      ferr(po, "bp_arg arg/w offset %d and type '%s'\n",
        offset, g_func_pp.arg[i].type.name);
  }
  else
  {
    if (g_stack_fsz == 0)
      ferr(po, "stack var access without stackframe\n");

    sf_ofs = g_stack_fsz + offset;
    if (sf_ofs < 0)
      ferr(po, "bp_stack offset %d/%d\n", offset, g_stack_fsz);

    if (is_lea)
      prefix = "(u32)&";
    else
      prefix = cast;

    switch (lmod)
    {
    case OPLM_BYTE:
      snprintf(buf, buf_size, "%ssf.b[%d%s%s]",
        prefix, sf_ofs, ofs_reg[0] ? "+" : "", ofs_reg);
      break;

    case OPLM_WORD:
      if ((sf_ofs & 1) || ofs_reg[0] != 0) {
        // known unaligned or possibly unaligned
        strcat(g_comment, " unaligned");
        if (prefix[0] == 0)
          prefix = "*(u16 *)&";
        snprintf(buf, buf_size, "%ssf.b[%d%s%s]",
          prefix, sf_ofs, ofs_reg[0] ? "+" : "", ofs_reg);
        break;
      }
      snprintf(buf, buf_size, "%ssf.w[%d]", prefix, sf_ofs / 2);
      break;

    case OPLM_DWORD:
      if ((sf_ofs & 3) || ofs_reg[0] != 0) {
        // known unaligned or possibly unaligned
        strcat(g_comment, " unaligned");
        if (prefix[0] == 0)
          prefix = "*(u32 *)&";
        snprintf(buf, buf_size, "%ssf.b[%d%s%s]",
          prefix, sf_ofs, ofs_reg[0] ? "+" : "", ofs_reg);
        break;
      }
      snprintf(buf, buf_size, "%ssf.d[%d]", prefix, sf_ofs / 4);
      break;

    default:
      ferr(po, "bp_stack bad lmod: %d\n", lmod);
    }
  }
}

static void check_label_read_ref(struct parsed_op *po, const char *name)
{
  if (IS_START(name, "sub_"))
    ferr(po, "func reference?\n");
}

static char *out_src_opr(char *buf, size_t buf_size,
	struct parsed_op *po, struct parsed_opr *popr, const char *cast,
  int is_lea)
{
  char tmp1[256], tmp2[256];
  char expr[256];
  int ret;

  if (cast == NULL)
    cast = "";

  switch (popr->type) {
  case OPT_REG:
    if (is_lea)
      ferr(po, "lea from reg?\n");

    switch (popr->lmod) {
    case OPLM_DWORD:
      snprintf(buf, buf_size, "%s%s", cast, opr_reg_p(po, popr));
      break;
    case OPLM_WORD:
      snprintf(buf, buf_size, "(u16)%s", opr_reg_p(po, popr));
      break;
    case OPLM_BYTE:
      if (popr->name[1] == 'h') // XXX..
        snprintf(buf, buf_size, "(u8)(%s >> 8)", opr_reg_p(po, popr));
      else
        snprintf(buf, buf_size, "(u8)%s", opr_reg_p(po, popr));
      break;
    default:
      ferr(po, "invalid src lmod: %d\n", popr->lmod);
    }
    break;

  case OPT_REGMEM:
    if (parse_stack_el(popr->name, NULL)
      || (g_bp_frame && IS_START(popr->name, "ebp-")))
    {
      stack_frame_access(po, popr->lmod, buf, buf_size,
        popr->name, cast, 1, is_lea);
      break;
    }

    strcpy(expr, popr->name);
    if (strchr(expr, '[')) {
      // special case: '[' can only be left for label[reg] form
      ret = sscanf(expr, "%[^[][%[^]]]", tmp1, tmp2);
      if (ret != 2)
        ferr(po, "parse failure for '%s'\n", expr);
      snprintf(expr, sizeof(expr), "(u32)&%s + %s", tmp1, tmp2);
    }

    // XXX: do we need more parsing?
    if (is_lea) {
      snprintf(buf, buf_size, "%s", expr);
      break;
    }

    if (cast[0] == 0)
      cast = lmod_cast_u_ptr(po, popr->lmod);
    snprintf(buf, buf_size, "%s(%s)", cast, expr);
    break;

  case OPT_LABEL:
    check_label_read_ref(po, popr->name);
    if (cast[0] == 0 && popr->is_ptr)
      cast = "(u32)";
    if (is_lea)
      snprintf(buf, buf_size, "(u32)&%s", popr->name);
    else
      snprintf(buf, buf_size, "%s%s%s", cast, popr->name,
        popr->is_array ? "[0]" : "");
    break;

  case OPT_OFFSET:
    check_label_read_ref(po, popr->name);
    if (cast[0] == 0)
      cast = "(u32)";
    if (is_lea)
      ferr(po, "lea an offset?\n");
    snprintf(buf, buf_size, "%s&%s", cast, popr->name);
    break;

  case OPT_CONST:
    if (is_lea)
      ferr(po, "lea from const?\n");

    snprintf(buf, buf_size, "%s", cast);
    ret = strlen(buf);
    printf_number(buf + ret, buf_size - ret, popr->val);
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
      if (popr->name[1] == 'h') // XXX..
        snprintf(buf, buf_size, "BYTE1(%s)", opr_reg_p(po, popr));
      else
        snprintf(buf, buf_size, "LOBYTE(%s)", opr_reg_p(po, popr));
      break;
    default:
      ferr(po, "invalid dst lmod: %d\n", popr->lmod);
    }
    break;

  case OPT_REGMEM:
    if (parse_stack_el(popr->name, NULL)
      || (g_bp_frame && IS_START(popr->name, "ebp-")))
    {
      stack_frame_access(po, popr->lmod, buf, buf_size,
        popr->name, "", 0, 0);
      break;
    }

    return out_src_opr(buf, buf_size, po, popr, NULL, 0);

  case OPT_LABEL:
    snprintf(buf, buf_size, "%s%s", popr->name,
      popr->is_array ? "[0]" : "");
    break;

  default:
    ferr(po, "invalid dst type: %d\n", popr->type);
  }

  return buf;
}

static char *out_src_opr_u32(char *buf, size_t buf_size,
	struct parsed_op *po, struct parsed_opr *popr)
{
  return out_src_opr(buf, buf_size, po, popr, NULL, 0);
}

static enum parsed_flag_op split_cond(struct parsed_op *po,
  enum op_op op, int *is_inv)
{
  *is_inv = 0;

  switch (op) {
  case OP_JO:
    return PFO_O;
  case OP_JC:
    return PFO_C;
  case OP_JZ:
    return PFO_Z;
  case OP_JBE:
    return PFO_BE;
  case OP_JS:
    return PFO_S;
  case OP_JP:
    return PFO_P;
  case OP_JL:
    return PFO_L;
  case OP_JLE:
    return PFO_LE;

  case OP_JNO:
    *is_inv = 1;
    return PFO_O;
  case OP_JNC:
    *is_inv = 1;
    return PFO_C;
  case OP_JNZ:
    *is_inv = 1;
    return PFO_Z;
  case OP_JA:
    *is_inv = 1;
    return PFO_BE;
  case OP_JNS:
    *is_inv = 1;
    return PFO_S;
  case OP_JNP:
    *is_inv = 1;
    return PFO_P;
  case OP_JGE:
    *is_inv = 1;
    return PFO_L;
  case OP_JG:
    *is_inv = 1;
    return PFO_LE;

  case OP_ADC:
  case OP_SBB:
    return PFO_C;

  default:
    ferr(po, "split_cond: bad op %d\n", op);
    return -1;
  }
}

static void out_test_for_cc(char *buf, size_t buf_size,
  struct parsed_op *po, enum parsed_flag_op pfo, int is_inv,
  enum opr_lenmod lmod, const char *expr)
{
  const char *cast, *scast;

  cast = lmod_cast_u(po, lmod);
  scast = lmod_cast_s(po, lmod);

  switch (pfo) {
  case PFO_Z:
  case PFO_BE: // CF=1||ZF=1; CF=0
    snprintf(buf, buf_size, "(%s%s %s 0)",
      cast, expr, is_inv ? "!=" : "==");
    break;

  case PFO_S:
  case PFO_L: // SF!=OF; OF=0
    snprintf(buf, buf_size, "(%s%s %s 0)",
      scast, expr, is_inv ? ">=" : "<");
    break;

  case PFO_LE: // ZF=1||SF!=OF; OF=0
    snprintf(buf, buf_size, "(%s%s %s 0)",
      scast, expr, is_inv ? ">" : "<=");
    break;

  default:
    ferr(po, "%s: unhandled parsed_flag_op: %d\n", __func__, pfo);
  }
}

static void out_cmp_for_cc(char *buf, size_t buf_size,
  struct parsed_op *po, enum parsed_flag_op pfo, int is_inv,
  enum opr_lenmod lmod, const char *expr1, const char *expr2)
{
  const char *cast, *scast;

  cast = lmod_cast_u(po, lmod);
  scast = lmod_cast_s(po, lmod);

  switch (pfo) {
  case PFO_C:
    // note: must be unsigned compare
    snprintf(buf, buf_size, "(%s%s %s %s%s)",
      cast, expr1, is_inv ? ">=" : "<", cast, expr2);
    break;

  case PFO_Z:
    snprintf(buf, buf_size, "(%s%s %s %s%s)",
      cast, expr1, is_inv ? "!=" : "==", cast, expr2);
    break;

  case PFO_BE: // !a
    // note: must be unsigned compare
    snprintf(buf, buf_size, "(%s%s %s %s%s)",
      cast, expr1, is_inv ? ">" : "<=", cast, expr2);
    break;

  // note: must be signed compare
  case PFO_S:
    snprintf(buf, buf_size, "(%s(%s - %s) %s 0)",
      scast, expr1, expr2, is_inv ? ">=" : "<");
    break;

  case PFO_L: // !ge
    snprintf(buf, buf_size, "(%s%s %s %s%s)",
      scast, expr1, is_inv ? ">=" : "<", scast, expr2);
    break;

  case PFO_LE:
    snprintf(buf, buf_size, "(%s%s %s %s%s)",
      scast, expr1, is_inv ? ">" : "<=", scast, expr2);
    break;

  default:
    ferr(po, "%s: unhandled parsed_flag_op: %d\n", __func__, pfo);
  }
}

static void out_cmp_test(char *buf, size_t buf_size,
  struct parsed_op *po, enum parsed_flag_op pfo, int is_inv)
{
  char buf1[256], buf2[256], buf3[256];

  if (po->op == OP_TEST) {
    if (IS(opr_name(po, 0), opr_name(po, 1))) {
      out_src_opr_u32(buf3, sizeof(buf3), po, &po->operand[0]);
    }
    else {
      out_src_opr_u32(buf1, sizeof(buf1), po, &po->operand[0]);
      out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]);
      snprintf(buf3, sizeof(buf3), "(%s & %s)", buf1, buf2);
    }
    out_test_for_cc(buf, buf_size, po, pfo, is_inv,
      po->operand[0].lmod, buf3);
  }
  else if (po->op == OP_CMP) {
    out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[0]);
    out_src_opr_u32(buf3, sizeof(buf3), po, &po->operand[1]);
    out_cmp_for_cc(buf, buf_size, po, pfo, is_inv,
      po->operand[0].lmod, buf2, buf3);
  }
  else
    ferr(po, "%s: unhandled op: %d\n", __func__, po->op);
}

static void propagate_lmod(struct parsed_op *po, struct parsed_opr *popr1,
	struct parsed_opr *popr2)
{
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
    case OP_ADC:
      return "+";
    case OP_SUB:
    case OP_SBB:
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

static void set_flag_no_dup(struct parsed_op *po, enum op_flags flag,
  enum op_flags flag_check)
{
  if (po->flags & flag)
    ferr(po, "flag %x already set\n", flag);
  if (po->flags & flag_check)
    ferr(po, "flag_check %x already set\n", flag_check);

  po->flags |= flag;
}

static int scan_for_pop(int i, int opcnt, const char *reg,
  int magic, int depth, int *maxdepth, int do_flags)
{
  struct parsed_op *po;
  int ret = 0;
  int j;

  for (; i < opcnt; i++) {
    po = &ops[i];
    if (po->cc_scratch == magic)
      break; // already checked
    po->cc_scratch = magic;

    if (po->flags & OPF_TAIL)
      return -1; // deadend

    if ((po->flags & OPF_RMD)
        || (po->op == OP_PUSH && po->argmask)) // arg push
      continue;

    if ((po->flags & OPF_JMP) && po->op != OP_CALL) {
      if (po->btj != NULL) {
        // jumptable
        for (j = 0; j < po->btj->count - 1; j++) {
          ret |= scan_for_pop(po->btj->d[j].bt_i, opcnt, reg, magic,
                   depth, maxdepth, do_flags);
          if (ret < 0)
            return ret; // dead end
        }
        // follow last jumptable entry
        i = po->btj->d[j].bt_i - 1;
        continue;
      }

      if (po->bt_i < 0) {
        ferr(po, "dead branch\n");
        return -1;
      }

      if (po->flags & OPF_CC) {
        ret |= scan_for_pop(po->bt_i, opcnt, reg, magic,
                 depth, maxdepth, do_flags);
        if (ret < 0)
          return ret; // dead end
      }
      else {
        i = po->bt_i - 1;
      }
      continue;
    }

    if ((po->op == OP_POP || po->op == OP_PUSH)
        && po->operand[0].type == OPT_REG
        && IS(po->operand[0].name, reg))
    {
      if (po->op == OP_PUSH) {
        depth++;
        if (depth > *maxdepth)
          *maxdepth = depth;
        if (do_flags)
          set_flag_no_dup(po, OPF_RSAVE, OPF_RMD);
      }
      else if (depth == 0) {
        if (do_flags)
          set_flag_no_dup(po, OPF_RMD, OPF_RSAVE);
        return 1;
      }
      else {
        depth--;
        if (depth < 0) // should not happen
          ferr(po, "fail with depth\n");
        if (do_flags)
          set_flag_no_dup(po, OPF_RSAVE, OPF_RMD);
      }
    }
  }

  return ret;
}

// scan for pop starting from 'ret' op (all paths)
static int scan_for_pop_ret(int i, int opcnt, const char *reg,
  int flag_set)
{
  int found = 0;
  int j;

  for (; i < opcnt; i++) {
    if (!(ops[i].flags & OPF_TAIL))
      continue;

    for (j = i - 1; j >= 0; j--) {
      if (ops[j].flags & OPF_RMD)
        continue;
      if (ops[j].flags & OPF_JMP)
        return -1;

      if (ops[j].op == OP_POP && ops[j].operand[0].type == OPT_REG
          && IS(ops[j].operand[0].name, reg))
      {
        found = 1;
        ops[j].flags |= flag_set;
        break;
      }

      if (g_labels[j][0] != 0)
        return -1;
    }
  }

  return found ? 0 : -1;
}

// is operand 'opr modified' by parsed_op 'po'?
static int is_opr_modified(const struct parsed_opr *opr,
  const struct parsed_op *po)
{
  if ((po->flags & OPF_RMD) || !(po->flags & OPF_DATA))
    return 0;

  if (opr->type == OPT_REG && po->operand[0].type == OPT_REG) {
    if (po->regmask_dst & (1 << opr->reg))
      return 1;
    else
      return 0;
  }

  return IS(po->operand[0].name, opr->name);
}

// is any operand of parsed_op 'po_test' modified by parsed_op 'po'?
static int is_any_opr_modified(const struct parsed_op *po_test,
  const struct parsed_op *po)
{
  int i;

  if ((po->flags & OPF_RMD) || !(po->flags & OPF_DATA))
    return 0;

  if (po_test->regmask_src & po->regmask_dst)
    return 1;

  for (i = 0; i < po_test->operand_cnt; i++)
    if (IS(po_test->operand[i].name, po->operand[0].name))
      return 1;

  return 0;
}

// scan for any po_test operand modification in range given
static int scan_for_mod(struct parsed_op *po_test, int i, int opcnt)
{
  for (; i < opcnt; i++) {
    if (is_any_opr_modified(po_test, &ops[i]))
      return i;
  }

  return -1;
}

// scan for po_test operand[0] modification in range given
static int scan_for_mod_opr0(struct parsed_op *po_test,
  int i, int opcnt)
{
  for (; i < opcnt; i++) {
    if (is_opr_modified(&po_test->operand[0], &ops[i]))
      return i;
  }

  return -1;
}

static int scan_for_flag_set(int i)
{
  for (; i >= 0; i--) {
    if (ops[i].flags & OPF_FLAGS)
      return i;

    if ((ops[i].flags & OPF_JMP) && !(ops[i].flags & OPF_CC))
      return -1;
    if (g_labels[i][0] != 0)
      return -1;
  }

  return -1;
}

// scan back for cdq, if anything modifies edx, fail
static int scan_for_cdq_edx(int i)
{
  for (; i >= 0; i--) {
    if (ops[i].op == OP_CDQ)
      return i;

    if (ops[i].regmask_dst & (1 << xDX))
      return -1;
    if (g_labels[i][0] != 0)
      return -1;
  }

  return -1;
}

static int scan_for_reg_clear(int i, int reg)
{
  for (; i >= 0; i--) {
    if (ops[i].op == OP_XOR
     && ops[i].operand[0].lmod == OPLM_DWORD
     && ops[i].operand[0].reg == ops[i].operand[1].reg
     && ops[i].operand[0].reg == reg)
      return i;

    if (ops[i].regmask_dst & (1 << reg))
      return -1;
    if (g_labels[i][0] != 0)
      return -1;
  }

  return -1;
}

// scan for positive, constant esp adjust
static int scan_for_esp_adjust(int i, int opcnt, int *adj)
{
  struct parsed_op *po;
  *adj = 0;

  for (; i < opcnt; i++) {
    po = &ops[i];

    if (po->op == OP_ADD && po->operand[0].reg == xSP) {
      if (po->operand[1].type != OPT_CONST)
        ferr(&ops[i], "non-const esp adjust?\n");
      *adj += po->operand[1].val;
      if (*adj & 3)
        ferr(&ops[i], "unaligned esp adjust: %x\n", *adj);
      return i;
    }
    else if (po->op == OP_PUSH)
      *adj -= lmod_bytes(po, po->operand[0].lmod);
    else if (po->op == OP_POP)
      *adj += lmod_bytes(po, po->operand[0].lmod);
    else if (po->flags & (OPF_JMP|OPF_TAIL)) {
      if (po->op != OP_CALL)
        return -1;
      if (po->operand[0].type != OPT_LABEL)
        return -1;
      // TODO: should only allow combining __cdecl calls..
    }

    if (g_labels[i][0] != 0)
      return -1;
  }

  return -1;
}

static int collect_call_args(struct parsed_op *po, int i,
  struct parsed_proto *pp, int *save_arg_vars, int arg,
  int need_op_saving)
{
  struct parsed_proto *pp_tmp;
  struct label_ref *lr;
  int ret = 0;
  int j;

  if (i < 0)
    ferr(po, "no refs for '%s'?\n", g_labels[i]);

  for (arg = 0; arg < pp->argc; arg++)
    if (pp->arg[arg].reg == NULL)
      break;

  for (j = i; j >= 0 && arg < pp->argc; )
  {
    if (g_labels[j][0] != 0) {
      lr = &g_label_refs[j];
      if (lr->next != NULL)
        need_op_saving = 1;
      for (; lr->next; lr = lr->next)
        ret |= collect_call_args(po, lr->i, pp, save_arg_vars,
                 arg, need_op_saving);

      if (j > 0 && ((ops[j - 1].flags & OPF_TAIL)
        || (ops[j - 1].flags & (OPF_JMP|OPF_CC)) == OPF_JMP))
      {
        // follow last branch in reverse
        j = lr->i;
        continue;
      }
      need_op_saving = 1;
      ret |= collect_call_args(po, lr->i, pp, save_arg_vars,
               arg, need_op_saving);
    }
    j--;

    if (ops[j].op == OP_CALL)
    {
      pp_tmp = ops[j].datap;
      if (pp_tmp == NULL)
        ferr(po, "arg collect hit unparsed call\n");
      if (pp_tmp->argc_stack > 0)
        ferr(po, "arg collect hit '%s' with %d stack args\n",
          opr_name(&ops[j], 0), pp_tmp->argc_stack);
    }
    else if ((ops[j].flags & OPF_TAIL)
        || (ops[j].flags & (OPF_JMP|OPF_CC)) == OPF_JMP)
    {
      break;
    }
    else if (ops[j].op == OP_PUSH)
    {
      pp->arg[arg].datap = &ops[j];
      if (!need_op_saving) {
        ret = scan_for_mod(&ops[j], j + 1, i);
        need_op_saving = (ret >= 0);
      }
      if (need_op_saving) {
        // mark this push as one that needs operand saving
        ops[j].flags &= ~OPF_RMD;
        ops[j].argmask |= 1 << arg;
        *save_arg_vars |= 1 << arg;
      }
      else
        ops[j].flags |= OPF_RMD;

      // next arg
      for (arg++; arg < pp->argc; arg++)
        if (pp->arg[arg].reg == NULL)
          break;
    }
  }

  if (arg < pp->argc) {
    ferr(po, "arg collect failed for '%s': %d/%d\n",
      pp->name, arg, pp->argc);
    ret = -1;
  }
  return ret;
}

static void add_label_ref(struct label_ref *lr, int op_i)
{
  struct label_ref *lr_new;

  if (lr->i == -1) {
    lr->i = op_i;
    return;
  }

  lr_new = calloc(1, sizeof(*lr_new));
  lr_new->i = op_i;
  lr->next = lr_new;
}

static void gen_func(FILE *fout, FILE *fhdr, const char *funcn, int opcnt)
{
  struct parsed_op *po, *delayed_flag_op = NULL, *tmp_op;
  struct parsed_opr *last_arith_dst = NULL;
  char buf1[256], buf2[256], buf3[256], cast[64];
  struct parsed_proto *pp, *pp_tmp;
  struct parsed_data *pd;
  const char *tmpname;
  enum parsed_flag_op pfo;
  int save_arg_vars = 0;
  int cmp_result_vars = 0;
  int need_mul_var = 0;
  int had_decl = 0;
  int label_pending = 0;
  int regmask_save = 0;
  int regmask_arg = 0;
  int regmask = 0;
  int pfomask = 0;
  int found = 0;
  int depth = 0;
  int no_output;
  int i, j, l;
  int dummy;
  int arg;
  int reg;
  int ret;

  g_bp_frame = g_sp_frame = g_stack_fsz = 0;

  ret = proto_parse(fhdr, funcn, &g_func_pp);
  if (ret)
    ferr(ops, "proto_parse failed for '%s'\n", funcn);

  fprintf(fout, "%s ", g_func_pp.ret_type.name);
  if (g_ida_func_attr & IDAFA_NORETURN)
    fprintf(fout, "noreturn ");
  fprintf(fout, "%s(", funcn);
  for (i = 0; i < g_func_pp.argc; i++) {
    if (i > 0)
      fprintf(fout, ", ");
    fprintf(fout, "%s a%d", g_func_pp.arg[i].type.name, i + 1);
  }
  if (g_func_pp.is_vararg) {
    if (i > 0)
      fprintf(fout, ", ");
    fprintf(fout, "...");
  }
  fprintf(fout, ")\n{\n");

  // pass1:
  // - handle ebp/esp frame, remove ops related to it
  if (ops[0].op == OP_PUSH && IS(opr_name(&ops[0], 0), "ebp")
      && ops[1].op == OP_MOV
      && IS(opr_name(&ops[1], 0), "ebp")
      && IS(opr_name(&ops[1], 1), "esp"))
  {
    int ecx_push = 0;

    g_bp_frame = 1;
    ops[0].flags |= OPF_RMD;
    ops[1].flags |= OPF_RMD;
    i = 2;

    if (ops[2].op == OP_SUB && IS(opr_name(&ops[2], 0), "esp")) {
      g_stack_fsz = opr_const(&ops[2], 1);
      ops[2].flags |= OPF_RMD;
      i++;
    }
    else {
      // another way msvc builds stack frame..
      i = 2;
      while (ops[i].op == OP_PUSH && IS(opr_name(&ops[i], 0), "ecx")) {
        g_stack_fsz += 4;
        ops[i].flags |= OPF_RMD;
        ecx_push++;
        i++;
      }
      // and another way..
      if (i == 2 && ops[i].op == OP_MOV && ops[i].operand[0].reg == xAX
          && ops[i].operand[1].type == OPT_CONST
          && ops[i + 1].op == OP_CALL
          && IS(opr_name(&ops[i + 1], 0), "__alloca_probe"))
      {
        g_stack_fsz += ops[i].operand[1].val;
        ops[i].flags |= OPF_RMD;
        i++;
        ops[i].flags |= OPF_RMD;
        i++;
      }
    }

    found = 0;
    do {
      for (; i < opcnt; i++)
        if (ops[i].op == OP_RET)
          break;
      if (i == opcnt && (ops[i - 1].flags & OPF_JMP) && found)
        break;

      if (ops[i - 1].op == OP_POP && IS(opr_name(&ops[i - 1], 0), "ebp"))
        ops[i - 1].flags |= OPF_RMD;
      else if (!(g_ida_func_attr & IDAFA_NORETURN))
        ferr(&ops[i - 1], "'pop ebp' expected\n");

      if (g_stack_fsz != 0) {
        if (ops[i - 2].op == OP_MOV
            && IS(opr_name(&ops[i - 2], 0), "esp")
            && IS(opr_name(&ops[i - 2], 1), "ebp"))
        {
          ops[i - 2].flags |= OPF_RMD;
        }
        else if (!(g_ida_func_attr & IDAFA_NORETURN))
          ferr(&ops[i - 2], "esp restore expected\n");

        if (ecx_push && ops[i - 3].op == OP_POP
          && IS(opr_name(&ops[i - 3], 0), "ecx"))
        {
          ferr(&ops[i - 3], "unexpected ecx pop\n");
        }
      }

      found = 1;
      i++;
    } while (i < opcnt);
  }
  else {
    for (i = 0; i < opcnt; i++) {
      if (ops[i].op == OP_PUSH || (ops[i].flags & (OPF_JMP|OPF_TAIL)))
        break;
      if (ops[i].op == OP_SUB && ops[i].operand[0].reg == xSP
        && ops[i].operand[1].type == OPT_CONST)
      {
        g_sp_frame = 1;
        break;
      }
    }

    if (g_sp_frame)
    {
      g_stack_fsz = ops[i].operand[1].val;
      ops[i].flags |= OPF_RMD;

      i++;
      do {
        for (; i < opcnt; i++)
          if (ops[i].op == OP_RET)
            break;
        if (ops[i - 1].op != OP_ADD
            || !IS(opr_name(&ops[i - 1], 0), "esp")
            || ops[i - 1].operand[1].type != OPT_CONST
            || ops[i - 1].operand[1].val != g_stack_fsz)
          ferr(&ops[i - 1], "'add esp' expected\n");
        ops[i - 1].flags |= OPF_RMD;

        i++;
      } while (i < opcnt);
    }
  }

  // pass2:
  // - resolve all branches
  for (i = 0; i < opcnt; i++) {
    po = &ops[i];
    po->bt_i = -1;
    po->btj = NULL;

    if ((po->flags & OPF_RMD) || !(po->flags & OPF_JMP)
        || po->op == OP_CALL || po->op == OP_RET)
      continue;

    if (po->operand[0].type == OPT_REGMEM) {
      char *p = strchr(po->operand[0].name, '[');
      if (p == NULL)
        ferr(po, "unhandled indirect branch\n");
      ret = p - po->operand[0].name;
      strncpy(buf1, po->operand[0].name, ret);
      buf1[ret] = 0;

      for (j = 0, pd = NULL; j < g_func_pd_cnt; j++) {
        if (IS(g_func_pd[j].label, buf1)) {
          pd = &g_func_pd[j];
          break;
        }
      }
      if (pd == NULL)
        ferr(po, "label '%s' not parsed?\n", buf1);
      if (pd->type != OPT_OFFSET)
        ferr(po, "label '%s' with non-offset data?\n", buf1);

      // find all labels, link
      for (j = 0; j < pd->count; j++) {
        for (l = 0; l < opcnt; l++) {
          if (g_labels[l][0] && IS(g_labels[l], pd->d[j].u.label)) {
            add_label_ref(&g_label_refs[l], i);
            pd->d[j].bt_i = l;
            break;
          }
        }
      }

      po->btj = pd;
      continue;
    }

    for (l = 0; l < opcnt; l++) {
      if (g_labels[l][0] && IS(po->operand[0].name, g_labels[l])) {
        add_label_ref(&g_label_refs[l], i);
        po->bt_i = l;
        break;
      }
    }

    if (po->bt_i != -1)
      continue;

    if (po->operand[0].type == OPT_LABEL) {
      // assume tail call
      po->op = OP_CALL;
      po->flags |= OPF_TAIL;
      continue;
    }

    ferr(po, "unhandled branch\n");
  }

  // pass3:
  // - process calls
  for (i = 0; i < opcnt; i++)
  {
    po = &ops[i];
    if (po->flags & OPF_RMD)
      continue;

    if (po->op == OP_CALL)
    {
      pp = calloc(1, sizeof(*pp));
      my_assert_not(pp, NULL);
      tmpname = opr_name(po, 0);
      if (po->operand[0].type != OPT_LABEL)
      {
        ret = scan_for_esp_adjust(i + 1, opcnt, &j);
        if (ret < 0)
          ferr(po, "non-__cdecl indirect call unhandled yet\n");
        j /= 4;
        if (j > ARRAY_SIZE(pp->arg))
          ferr(po, "esp adjust too large?\n");
        pp->ret_type.name = strdup("int");
        pp->argc = pp->argc_stack = j;
        for (arg = 0; arg < pp->argc; arg++)
          pp->arg[arg].type.name = strdup("int");
      }
      else {
        ret = proto_parse(fhdr, tmpname, pp);
        if (ret)
          ferr(po, "proto_parse failed for call '%s'\n", tmpname);
      }

      // look for and make use of esp adjust
      ret = -1;
      if (!pp->is_stdcall && pp->argc_stack > 0)
        ret = scan_for_esp_adjust(i + 1, opcnt, &j);
      if (ret >= 0) {
        if (pp->is_vararg) {
          if (j / 4 < pp->argc_stack)
            ferr(po, "esp adjust is too small: %x < %x\n",
              j, pp->argc_stack * 4);
          // modify pp to make it have varargs as normal args
          arg = pp->argc;
          pp->argc += j / 4 - pp->argc_stack;
          for (; arg < pp->argc; arg++) {
            pp->arg[arg].type.name = strdup("int");
            pp->argc_stack++;
          }
          if (pp->argc > ARRAY_SIZE(pp->arg))
            ferr(po, "too many args for '%s'\n", tmpname);
        }
        if (pp->argc_stack != j / 4)
          ferr(po, "stack tracking failed for '%s': %x %x\n",
            tmpname, pp->argc_stack * 4, j);

        ops[ret].flags |= OPF_RMD;
        // a bit of a hack, but deals with use of
        // single adj for multiple calls
        ops[ret].operand[1].val -= j;
      }
      else if (pp->is_vararg)
        ferr(po, "missing esp_adjust for vararg func '%s'\n",
          pp->name);

      // can't call functions with non-__cdecl callbacks yet
      for (arg = 0; arg < pp->argc; arg++) {
        if (pp->arg[arg].fptr != NULL) {
          pp_tmp = pp->arg[arg].fptr;
          if (pp_tmp->is_stdcall || pp_tmp->argc != pp_tmp->argc_stack)
            ferr(po, "'%s' has a non-__cdecl callback\n", tmpname);
        }
      }

      collect_call_args(po, i, pp, &save_arg_vars, 0, 0);
      po->datap = pp;
    }
  }

  // pass4:
  // - find POPs for PUSHes, rm both
  // - scan for all used registers
  // - find flag set ops for their users
  // - declare indirect functions
  for (i = 0; i < opcnt; i++) {
    po = &ops[i];
    if (po->flags & OPF_RMD)
      continue;

    if (po->op == OP_PUSH
        && po->argmask == 0 && !(po->flags & OPF_RSAVE)
        && po->operand[0].type == OPT_REG)
    {
      reg = po->operand[0].reg;
      if (reg < 0)
        ferr(po, "reg not set for push?\n");

      depth = 0;
      ret = scan_for_pop(i + 1, opcnt,
              po->operand[0].name, i + opcnt, 0, &depth, 0);
      if (ret == 1) {
        if (depth > 1)
          ferr(po, "too much depth: %d\n", depth);
        if (depth > 0)
          regmask_save |= 1 << reg;

        po->flags |= OPF_RMD;
        scan_for_pop(i + 1, opcnt, po->operand[0].name,
          i + opcnt * 2, 0, &depth, 1);
        continue;
      }
      ret = scan_for_pop_ret(i + 1, opcnt, po->operand[0].name, 0);
      if (ret == 0) {
        arg = OPF_RMD;
        if (regmask & (1 << reg)) {
          if (regmask_save & (1 << reg))
            ferr(po, "%s already saved?\n", po->operand[0].name);
          arg = OPF_RSAVE;
        }
        po->flags |= arg;
        scan_for_pop_ret(i + 1, opcnt, po->operand[0].name, arg);
        continue;
      }
    }

    regmask |= po->regmask_src | po->regmask_dst;

    if (po->flags & OPF_CC)
    {
      ret = scan_for_flag_set(i - 1);
      if (ret < 0)
        ferr(po, "unable to trace flag setter\n");

      tmp_op = &ops[ret]; // flag setter
      pfo = split_cond(po, po->op, &dummy);
      pfomask = 0;

      // to get nicer code, we try to delay test and cmp;
      // if we can't because of operand modification, or if we
      // have math op, make it calculate flags explicitly
      if (tmp_op->op == OP_TEST || tmp_op->op == OP_CMP) {
        if (scan_for_mod(tmp_op, ret + 1, i) >= 0)
          pfomask = 1 << pfo;
      }
      else if (tmp_op->op == OP_CMPS) {
        pfomask = 1 << PFO_Z;
      }
      else {
        if ((pfo != PFO_Z && pfo != PFO_S && pfo != PFO_P)
            || scan_for_mod_opr0(tmp_op, ret + 1, i) >= 0)
          pfomask = 1 << pfo;
      }
      if (pfomask) {
        tmp_op->pfomask |= pfomask;
        cmp_result_vars |= pfomask;
        po->datap = tmp_op;
      }

      if (po->op == OP_ADC || po->op == OP_SBB)
        cmp_result_vars |= 1 << PFO_C;
    }
    else if (po->op == OP_MUL
      || (po->op == OP_IMUL && po->operand_cnt == 1))
    {
      need_mul_var = 1;
    }
    else if (po->op == OP_CALL && po->operand[0].type != OPT_LABEL) {
      pp = po->datap;
      my_assert_not(pp, NULL);
      fprintf(fout, "  %s (*icall%d)(", pp->ret_type.name, i);
      for (j = 0; j < pp->argc; j++) {
        if (j > 0)
          fprintf(fout, ", ");
        fprintf(fout, "%s a%d", pp->arg[j].type.name, j + 1);
      }
      fprintf(fout, ");\n");
    }
  }

  // output LUTs/jumptables
  for (i = 0; i < g_func_pd_cnt; i++) {
    pd = &g_func_pd[i];
    fprintf(fout, "  static const ");
    if (pd->type == OPT_OFFSET) {
      fprintf(fout, "void *jt_%s[] =\n    { ", pd->label);

      for (j = 0; j < pd->count; j++) {
        if (j > 0)
          fprintf(fout, ", ");
        fprintf(fout, "&&%s", pd->d[j].u.label);
      }
    }
    else {
      fprintf(fout, "%s %s[] =\n    { ",
        lmod_type_u(ops, pd->lmod), pd->label);

      for (j = 0; j < pd->count; j++) {
        if (j > 0)
          fprintf(fout, ", ");
        fprintf(fout, "%u", pd->d[j].u.val);
      }
    }
    fprintf(fout, " };\n");
  }

  // declare stack frame, va_arg
  if (g_stack_fsz)
    fprintf(fout, "  union { u32 d[%d]; u16 w[%d]; u8 b[%d]; } sf;\n",
      (g_stack_fsz + 3) / 4, (g_stack_fsz + 1) / 2, g_stack_fsz);

  if (g_func_pp.is_vararg)
    fprintf(fout, "  va_list ap;\n");

  // declare arg-registers
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

  // declare other regs - special case for eax
  if (!((regmask | regmask_arg) & 1)
   && !IS(g_func_pp.ret_type.name, "void"))
  {
    fprintf(fout, "  u32 eax = 0;\n");
    had_decl = 1;
  }

  regmask &= ~regmask_arg;
  regmask &= ~(1 << xSP);
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

  if (regmask_save) {
    for (reg = 0; reg < 8; reg++) {
      if (regmask_save & (1 << reg)) {
        fprintf(fout, "  u32 s_%s;\n", regs_r32[reg]);
        had_decl = 1;
      }
    }
  }

  if (save_arg_vars) {
    for (reg = 0; reg < 32; reg++) {
      if (save_arg_vars & (1 << reg)) {
        fprintf(fout, "  u32 s_a%d;\n", reg + 1);
        had_decl = 1;
      }
    }
  }

  if (cmp_result_vars) {
    for (i = 0; i < 8; i++) {
      if (cmp_result_vars & (1 << i)) {
        fprintf(fout, "  u32 cond_%s;\n", parsed_flag_op_names[i]);
        had_decl = 1;
      }
    }
  }

  if (need_mul_var) {
    fprintf(fout, "  u64 mul_tmp;\n");
    had_decl = 1;
  }

  if (had_decl)
    fprintf(fout, "\n");

  if (g_func_pp.is_vararg) {
    if (g_func_pp.argc_stack == 0)
      ferr(ops, "vararg func without stack args?\n");
    fprintf(fout, "  va_start(ap, a%d);\n", g_func_pp.argc);
  }

  // output ops
  for (i = 0; i < opcnt; i++)
  {
    if (g_labels[i][0] != 0 && g_label_refs[i].i != -1) {
      fprintf(fout, "\n%s:\n", g_labels[i]);
      label_pending = 1;
    }

    po = &ops[i];
    if (po->flags & OPF_RMD)
      continue;

    no_output = 0;

    #define assert_operand_cnt(n_) \
      if (po->operand_cnt != n_) \
        ferr(po, "operand_cnt is %d/%d\n", po->operand_cnt, n_)

    // conditional/flag using op?
    if (po->flags & OPF_CC)
    {
      int is_delayed = 0;
      int is_inv = 0;

      pfo = split_cond(po, po->op, &is_inv);

      // we go through all this trouble to avoid using parsed_flag_op,
      // which makes generated code much nicer
      if (delayed_flag_op != NULL)
      {
        out_cmp_test(buf1, sizeof(buf1), delayed_flag_op, pfo, is_inv);
        is_delayed = 1;
      }
      else if (last_arith_dst != NULL
        && (pfo == PFO_Z || pfo == PFO_S || pfo == PFO_P))
      {
        out_src_opr_u32(buf3, sizeof(buf3), po, last_arith_dst);
        out_test_for_cc(buf1, sizeof(buf1), po, pfo, is_inv,
          last_arith_dst->lmod, buf3);
        is_delayed = 1;
      }
      else if (po->datap != NULL) {
        // use preprocessed flag calc results
        tmp_op = po->datap;
        if (!tmp_op || !(tmp_op->pfomask & (1 << pfo)))
          ferr(po, "not prepared for pfo %d\n", pfo);

        // note: is_inv was not yet applied
        snprintf(buf1, sizeof(buf1), "(%scond_%s)",
          is_inv ? "!" : "", parsed_flag_op_names[pfo]);
      }
      else {
        ferr(po, "all methods of finding comparison failed\n");
      }
 
      if (po->flags & OPF_JMP) {
        fprintf(fout, "  if %s\n", buf1);
      }
      else if (po->op == OP_ADC || po->op == OP_SBB) {
        if (is_delayed)
          fprintf(fout, "  cond_%s = %s;\n",
            parsed_flag_op_names[pfo], buf1);
      }
      else if (po->flags & OPF_DATA) { // SETcc
        out_dst_opr(buf2, sizeof(buf2), po, &po->operand[0]);
        fprintf(fout, "  %s = %s;", buf2, buf1);
      }
      else {
        ferr(po, "unhandled conditional op\n");
      }
    }

    pfomask = po->pfomask;

    switch (po->op)
    {
      case OP_MOV:
        assert_operand_cnt(2);
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        fprintf(fout, "  %s = %s;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
            out_src_opr(buf2, sizeof(buf2), po, &po->operand[1],
              po->operand[0].is_ptr ? "(void *)" : "", 0));
        break;

      case OP_LEA:
        assert_operand_cnt(2);
        po->operand[1].lmod = OPLM_DWORD; // always
        fprintf(fout, "  %s = %s;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
            out_src_opr(buf2, sizeof(buf2), po, &po->operand[1],
              NULL, 1));
        break;

      case OP_MOVZX:
        assert_operand_cnt(2);
        fprintf(fout, "  %s = %s;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
            out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]));
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
            out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]));
        break;

      case OP_NOT:
        assert_operand_cnt(1);
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        fprintf(fout, "  %s = ~%s;", buf1, buf1);
        break;

      case OP_CDQ:
        assert_operand_cnt(2);
        fprintf(fout, "  %s = (s32)%s >> 31;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
            out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]));
        strcpy(g_comment, "cdq");
        break;

      case OP_STOS:
        // assumes DF=0
        assert_operand_cnt(3);
        if (po->flags & OPF_REP) {
          fprintf(fout, "  for (; ecx != 0; ecx--, edi += %d)\n",
            lmod_bytes(po, po->operand[0].lmod));
          fprintf(fout, "    %sedi = eax;",
            lmod_cast_u_ptr(po, po->operand[0].lmod));
          strcpy(g_comment, "rep stos");
        }
        else {
          fprintf(fout, "    %sedi = eax; edi += %d;",
            lmod_cast_u_ptr(po, po->operand[0].lmod),
            lmod_bytes(po, po->operand[0].lmod));
          strcpy(g_comment, "stos");
        }
        break;

      case OP_MOVS:
        // assumes DF=0
        assert_operand_cnt(3);
        j = lmod_bytes(po, po->operand[0].lmod);
        strcpy(buf1, lmod_cast_u_ptr(po, po->operand[0].lmod));
        if (po->flags & OPF_REP) {
          fprintf(fout,
            "  for (; ecx != 0; ecx--, edi += %d, esi += %d)\n",
            j, j);
          fprintf(fout,
            "    %sedi = %sesi;", buf1, buf1);
          strcpy(g_comment, "rep movs");
        }
        else {
          fprintf(fout, "    %sedi = %sesi; edi += %d; esi += %d;",
            buf1, buf1, j, j);
          strcpy(g_comment, "movs");
        }
        break;

      case OP_CMPS:
        // assumes DF=0
        // repe ~ repeat while ZF=1
        assert_operand_cnt(3);
        j = lmod_bytes(po, po->operand[0].lmod);
        strcpy(buf1, lmod_cast_u_ptr(po, po->operand[0].lmod));
        if (po->flags & OPF_REP) {
          fprintf(fout,
            "  for (; ecx != 0; ecx--, edi += %d, esi += %d)\n",
            j, j);
          fprintf(fout,
            "    if ((cond_z = (%sedi == %sesi)) %s 0)\n",
              buf1, buf1, (po->flags & OPF_REPZ) ? "==" : "!=");
          fprintf(fout,
            "      break;");
          snprintf(g_comment, sizeof(g_comment), "rep%s cmps",
            (po->flags & OPF_REPZ) ? "e" : "ne");
        }
        else {
          fprintf(fout,
            "    cond_z = (%sedi = %sesi); edi += %d; esi += %d;",
            buf1, buf1, j, j);
          strcpy(g_comment, "cmps");
        }
        pfomask &= ~(1 << PFO_Z);
        last_arith_dst = NULL;
        delayed_flag_op = NULL;
        break;

      // arithmetic w/flags
      case OP_ADD:
      case OP_SUB:
      case OP_AND:
      case OP_OR:
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        // fallthrough
      case OP_SHL:
      case OP_SHR:
      dualop_arith:
        assert_operand_cnt(2);
        fprintf(fout, "  %s %s= %s;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
            op_to_c(po),
            out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]));
        last_arith_dst = &po->operand[0];
        delayed_flag_op = NULL;
        break;

      case OP_SAR:
        assert_operand_cnt(2);
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        fprintf(fout, "  %s = %s%s >> %s;", buf1,
          lmod_cast_s(po, po->operand[0].lmod), buf1,
          out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]));
        last_arith_dst = &po->operand[0];
        delayed_flag_op = NULL;
        break;

      case OP_ROL:
      case OP_ROR:
        assert_operand_cnt(2);
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        if (po->operand[1].type == OPT_CONST) {
          j = po->operand[1].val;
          j %= lmod_bytes(po, po->operand[0].lmod) * 8;
          fprintf(fout, po->op == OP_ROL ?
            "  %s = (%s << %d) | (%s >> %d);" :
            "  %s = (%s >> %d) | (%s << %d);",
            buf1, buf1, j, buf1,
            lmod_bytes(po, po->operand[0].lmod) * 8 - j);
        }
        else
          ferr(po, "TODO\n");
        last_arith_dst = &po->operand[0];
        delayed_flag_op = NULL;
        break;

      case OP_XOR:
        assert_operand_cnt(2);
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        if (IS(opr_name(po, 0), opr_name(po, 1))) {
          // special case for XOR
          fprintf(fout, "  %s = 0;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]));
          last_arith_dst = &po->operand[0];
          delayed_flag_op = NULL;
          break;
        }
        goto dualop_arith;

      case OP_ADC:
      case OP_SBB:
        assert_operand_cnt(2);
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        fprintf(fout, "  %s %s= %s + cond_c;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
            op_to_c(po),
            out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]));
        last_arith_dst = &po->operand[0];
        delayed_flag_op = NULL;
        break;

      case OP_INC:
      case OP_DEC:
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        if (po->operand[0].type == OPT_REG) {
          strcpy(buf2, po->op == OP_INC ? "++" : "--");
          fprintf(fout, "  %s%s;", buf1, buf2);
        }
        else {
          strcpy(buf2, po->op == OP_INC ? "+" : "-");
          fprintf(fout, "  %s %s= 1;", buf1, buf2);
        }
        last_arith_dst = &po->operand[0];
        delayed_flag_op = NULL;
        break;

      case OP_NEG:
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[0]);
        fprintf(fout, "  %s = -%s%s;", buf1,
          lmod_cast_s(po, po->operand[0].lmod), buf2);
        last_arith_dst = &po->operand[0];
        delayed_flag_op = NULL;
        if (pfomask & (1 << PFO_C)) {
          fprintf(fout, "\n  cond_c = (%s != 0);", buf1);
          pfomask &= ~(1 << PFO_C);
        }
        break;

      case OP_IMUL:
        if (po->operand_cnt == 2)
          goto dualop_arith;
        if (po->operand_cnt == 3)
          ferr(po, "TODO imul3\n");
        // fallthrough
      case OP_MUL:
        assert_operand_cnt(1);
        strcpy(buf1, po->op == OP_IMUL ? "(s64)(s32)" : "(u64)");
        fprintf(fout, "  mul_tmp = %seax * %s%s;\n", buf1, buf1,
          out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[0]));
        fprintf(fout, "  edx = mul_tmp >> 32;\n");
        fprintf(fout, "  eax = mul_tmp;");
        last_arith_dst = NULL;
        delayed_flag_op = NULL;
        break;

      case OP_DIV:
      case OP_IDIV:
        assert_operand_cnt(1);
        if (po->operand[0].lmod != OPLM_DWORD)
          ferr(po, "unhandled lmod %d\n", po->operand[0].lmod);

        // 32bit division is common, look for it
        if (po->op == OP_DIV)
          ret = scan_for_reg_clear(i - 1, xDX);
        else
          ret = scan_for_cdq_edx(i - 1);
        if (ret >= 0) {
          out_src_opr_u32(buf1, sizeof(buf1), po, &po->operand[0]);
          strcpy(buf2, lmod_cast(po, po->operand[0].lmod,
            po->op == OP_IDIV));
          fprintf(fout, "  edx = %seax %% %s%s;\n", buf2, buf2, buf1);
          fprintf(fout, "  eax = %seax / %s%s;", buf2, buf2, buf1);
        }
        else
          ferr(po, "TODO 64bit divident\n");
        last_arith_dst = NULL;
        delayed_flag_op = NULL;
        break;

      case OP_TEST:
      case OP_CMP:
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        if (pfomask != 0) {
          for (j = 0; j < 8; j++) {
            if (pfomask & (1 << j)) {
              out_cmp_test(buf1, sizeof(buf1), po, j, 0);
              fprintf(fout, "  cond_%s = %s;",
                parsed_flag_op_names[j], buf1);
            }
          }
          pfomask = 0;
        }
        else
          no_output = 1;
        last_arith_dst = NULL;
        delayed_flag_op = po;
        break;

      // note: we reuse OP_Jcc for SETcc, only flags differ
      case OP_JO ... OP_JG:
        if (po->flags & OPF_JMP)
          fprintf(fout, "    goto %s;", po->operand[0].name);
        // else SETcc - should already be handled
        break;

      case OP_JMP:
        assert_operand_cnt(1);
        if (po->operand[0].type == OPT_REGMEM) {
          ret = sscanf(po->operand[0].name, "%[^[][%[^*]*4]",
                  buf1, buf2);
          if (ret != 2)
            ferr(po, "parse failure for jmp '%s'\n",
              po->operand[0].name);
          fprintf(fout, "  goto *jt_%s[%s];", buf1, buf2);
          break;
        }
        else if (po->operand[0].type != OPT_LABEL)
          ferr(po, "unhandled jmp type\n");

        fprintf(fout, "  goto %s;", po->operand[0].name);
        break;

      case OP_CALL:
        assert_operand_cnt(1);
        pp = po->datap;
        if (pp == NULL)
          ferr(po, "NULL pp\n");

        if (po->operand[0].type != OPT_LABEL)
          fprintf(fout, "  icall%d = (void *)%s;\n", i,
            out_src_opr_u32(buf1, sizeof(buf1), po, &po->operand[0]));

        fprintf(fout, "  ");
        if (!IS(pp->ret_type.name, "void")) {
          if (po->flags & OPF_TAIL)
            fprintf(fout, "return ");
          else
            fprintf(fout, "eax = ");
          if (pp->ret_type.is_ptr)
            fprintf(fout, "(u32)");
        }

        if (po->operand[0].type != OPT_LABEL) {
          fprintf(fout, "icall%d(", i);
        }
        else {
          if (pp->name[0] == 0)
            ferr(po, "missing pp->name\n");
          fprintf(fout, "%s(", pp->name);
        }

        for (arg = 0; arg < pp->argc; arg++) {
          if (arg > 0)
            fprintf(fout, ", ");

          cast[0] = 0;
          if (pp->arg[arg].type.is_ptr)
            snprintf(cast, sizeof(cast), "(%s)", pp->arg[arg].type.name);

          if (pp->arg[arg].reg != NULL) {
            fprintf(fout, "%s%s", cast, pp->arg[arg].reg);
            continue;
          }

          // stack arg
          tmp_op = pp->arg[arg].datap;
          if (tmp_op == NULL)
            ferr(po, "parsed_op missing for arg%d\n", arg);
          if (tmp_op->argmask) {
            fprintf(fout, "%ss_a%d", cast, arg + 1);
          }
          else {
            fprintf(fout, "%s",
              out_src_opr(buf1, sizeof(buf1),
                tmp_op, &tmp_op->operand[0], cast, 0));
          }
        }
        fprintf(fout, ");");

        if (po->flags & OPF_TAIL) {
          strcpy(g_comment, "tailcall");
          if (IS(pp->ret_type.name, "void")
           && !(g_ida_func_attr & IDAFA_NORETURN))
          {
            fprintf(fout, "\n  return;");
            strcpy(g_comment, "^ tailcall");
          }
        }
        delayed_flag_op = NULL;
        last_arith_dst = NULL;
        break;

      case OP_RET:
        if (g_func_pp.is_vararg)
          fprintf(fout, "  va_end(ap);\n");
 
        if (IS(g_func_pp.ret_type.name, "void")) {
          if (i != opcnt - 1 || label_pending)
            fprintf(fout, "  return;");
        }
        else if (g_func_pp.ret_type.is_ptr) {
          fprintf(fout, "  return (%s)eax;",
            g_func_pp.ret_type.name);
        }
        else
          fprintf(fout, "  return eax;");
        break;

      case OP_PUSH:
        if (po->argmask) {
          // special case - saved func arg
          out_src_opr_u32(buf1, sizeof(buf1), po, &po->operand[0]);
          for (j = 0; j < 32; j++) {
            if (po->argmask & (1 << j))
              fprintf(fout, "  s_a%d = %s;", j + 1, buf1);
          }
          break;
        }
        else if (po->flags & OPF_RSAVE) {
          out_src_opr_u32(buf1, sizeof(buf1), po, &po->operand[0]);
          fprintf(fout, "  s_%s = %s;", buf1, buf1);
          break;
        }
        if (!(g_ida_func_attr & IDAFA_NORETURN))
          ferr(po, "stray push encountered\n");
        no_output = 1;
        break;

      case OP_POP:
        if (po->flags & OPF_RSAVE) {
          out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
          fprintf(fout, "  %s = s_%s;", buf1, buf1);
          break;
        }
        ferr(po, "stray pop encountered\n");
        break;

      case OP_NOP:
        break;

      default:
        no_output = 1;
        ferr(po, "unhandled op type %d, flags %x\n",
          po->op, po->flags);
        break;
    }

    // some sanity checking
    if ((po->flags & OPF_REP) && po->op != OP_STOS
        && po->op != OP_MOVS && po->op != OP_CMPS)
      ferr(po, "unexpected rep\n");
    if ((po->flags & (OPF_REPZ|OPF_REPNZ)) && po->op != OP_CMPS)
      ferr(po, "unexpected repz/repnz\n");

    if (g_comment[0] != 0) {
      fprintf(fout, "  // %s", g_comment);
      g_comment[0] = 0;
      no_output = 0;
    }
    if (!no_output)
      fprintf(fout, "\n");

    if (pfomask != 0)
      ferr(po, "missed flag calc, pfomask=%x\n", pfomask);

    // see is delayed flag stuff is still valid
    if (delayed_flag_op != NULL && delayed_flag_op != po) {
      if (is_any_opr_modified(delayed_flag_op, po))
        delayed_flag_op = NULL;
    }

    if (last_arith_dst != NULL && last_arith_dst != &po->operand[0]) {
      if (is_opr_modified(last_arith_dst, po))
        last_arith_dst = NULL;
    }

    label_pending = 0;
  }

  fprintf(fout, "}\n\n");

  // cleanup
  for (i = 0; i < opcnt; i++) {
    struct label_ref *lr, *lr_del;

    lr = g_label_refs[i].next;
    while (lr != NULL) {
      lr_del = lr;
      lr = lr->next;
      free(lr_del);
    }
    g_label_refs[i].i = -1;
    g_label_refs[i].next = NULL;

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

static void set_label(int i, const char *name)
{
  const char *p;
  int len;

  len = strlen(name);
  p = strchr(name, ':');
  if (p != NULL)
    len = p - name;

  if (len > sizeof(g_labels[0]) - 1)
    aerr("label '%s' too long: %d\n", name, len);
  if (g_labels[i][0] != 0 && !IS_START(g_labels[i], "algn_"))
    aerr("dupe label '%s' vs '%s'?\n", name, g_labels[i]);
  memcpy(g_labels[i], name, len);
  g_labels[i][len] = 0;
}

// '=' needs special treatment..
static char *next_word_s(char *w, size_t wsize, char *s)
{
	size_t i;

	s = sskip(s);

	for (i = 0; i < wsize - 1; i++) {
		if (s[i] == 0 || my_isblank(s[i]) || (s[i] == '=' && i > 0))
			break;
		w[i] = s[i];
	}
	w[i] = 0;

	if (s[i] != 0 && !my_isblank(s[i]) && s[i] != '=')
		printf("warning: '%s' truncated\n", w);

	return s + i;
}

struct chunk_item {
  char *name;
  long fptr;
};

static int cmp_chunks(const void *p1, const void *p2)
{
  const struct chunk_item *c1 = p1, *c2 = p2;
  return strcmp(c1->name, c2->name);
}

static int cmpstringp(const void *p1, const void *p2)
{
  return strcmp(*(char * const *)p1, *(char * const *)p2);
}

int main(int argc, char *argv[])
{
  FILE *fout, *fasm, *frlist;
  struct parsed_data *pd = NULL;
  int pd_alloc = 0;
  char **rlist = NULL;
  int rlist_len = 0;
  int rlist_alloc = 0;
  struct chunk_item *func_chunks;
  int func_chunks_used = 0;
  int func_chunks_sorted = 0;
  int func_chunk_cnt = 0;
  int func_chunk_alloc;
  int func_chunk_i = -1;
  long func_chunk_ret = 0;
  char line[256];
  char words[16][256];
  enum opr_lenmod lmod;
  int in_func = 0;
  int pending_endp = 0;
  int skip_func = 0;
  int skip_warned = 0;
  int eq_alloc;
  int verbose = 0;
  int arg_out;
  int arg = 1;
  int pi = 0;
  int i, j;
  int ret, len;
  char *p;
  int wordc;

  if (argv[1] && IS(argv[1], "-v")) {
    verbose = 1;
    arg++;
  }

  if (argc < arg + 3) {
    printf("usage:\n%s [-v] <.c> <.asm> <hdrf> [rlist]*\n",
      argv[0]);
    return 1;
  }

  arg_out = arg++;

  asmfn = argv[arg++];
  fasm = fopen(asmfn, "r");
  my_assert_not(fasm, NULL);

  hdrfn = argv[arg++];
  g_fhdr = fopen(hdrfn, "r");
  my_assert_not(g_fhdr, NULL);

  rlist_alloc = 64;
  rlist = malloc(rlist_alloc * sizeof(rlist[0]));
  my_assert_not(rlist, NULL);
  // needs special handling..
  rlist[rlist_len++] = "__alloca_probe";

  func_chunk_alloc = 32;
  func_chunks = malloc(func_chunk_alloc * sizeof(func_chunks[0]));
  my_assert_not(func_chunks, NULL);

  for (; arg < argc; arg++) {
    frlist = fopen(argv[arg], "r");
    my_assert_not(frlist, NULL);

    while (fgets(line, sizeof(line), frlist)) {
      p = sskip(line);
      if (*p == 0 || *p == ';' || *p == '#')
        continue;

      p = next_word(words[0], sizeof(words[0]), p);
      if (words[0][0] == 0)
        continue;

      if (rlist_len >= rlist_alloc) {
        rlist_alloc = rlist_alloc * 2 + 64;
        rlist = realloc(rlist, rlist_alloc * sizeof(rlist[0]));
        my_assert_not(rlist, NULL);
      }
      rlist[rlist_len++] = strdup(words[0]);
    }

    fclose(frlist);
    frlist = NULL;
  }

  if (rlist_len > 0)
    qsort(rlist, rlist_len, sizeof(rlist[0]), cmpstringp);

  fout = fopen(argv[arg_out], "w");
  my_assert_not(fout, NULL);

  eq_alloc = 128;
  g_eqs = malloc(eq_alloc * sizeof(g_eqs[0]));
  my_assert_not(g_eqs, NULL);

  for (i = 0; i < ARRAY_SIZE(g_label_refs); i++) {
    g_label_refs[i].i = -1;
    g_label_refs[i].next = NULL;
  }

  while (fgets(line, sizeof(line), fasm))
  {
    wordc = 0;
    asmln++;

    p = sskip(line);
    if (*p == 0)
      continue;

    if (*p == ';')
    {
      // get rid of random tabs
      for (i = 0; p[i] != 0; i++)
        if (p[i] == '\t')
          p[i] = ' ';

      if (p[2] == '=' && IS_START(p, "; =============== S U B"))
        goto do_pending_endp; // eww..

      if (p[2] == 'A' && IS_START(p, "; Attributes:"))
      {
        static const char *attrs[] = {
          "bp-based frame",
          "library function",
          "static",
          "noreturn",
          "thunk",
          "fpd=",
        };

        // parse IDA's attribute-list comment
        g_ida_func_attr = 0;
        p = sskip(p + 13);

        for (; *p != 0; p = sskip(p)) {
          for (i = 0; i < ARRAY_SIZE(attrs); i++) {
            if (!strncmp(p, attrs[i], strlen(attrs[i]))) {
              g_ida_func_attr |= 1 << i;
              p += strlen(attrs[i]);
              break;
            }
          }
          if (i == ARRAY_SIZE(attrs)) {
            anote("unparsed IDA attr: %s\n", p);
            break;
          }
          if (IS(attrs[i], "fpd=")) {
            p = next_word(words[0], sizeof(words[0]), p);
            // ignore for now..
          }
        }
      }
      else if (p[2] == 'S' && IS_START(p, "; START OF FUNCTION CHUNK FOR "))
      {
        p += 30;
        next_word(words[0], sizeof(words[0]), p);
        if (words[0][0] == 0)
          aerr("missing nam for func chunk?\n");
        if (func_chunk_cnt >= func_chunk_alloc) {
          func_chunk_alloc *= 2;
          func_chunks = realloc(func_chunks,
            func_chunk_alloc * sizeof(func_chunks[0]));
          my_assert_not(func_chunks, NULL);
        }
        func_chunks[func_chunk_cnt].fptr = ftell(fasm);
        func_chunks[func_chunk_cnt].name = strdup(words[0]);
        func_chunk_cnt++;
        func_chunks_sorted = 0;
      }
      else if (p[2] == 'E' && IS_START(p, "; END OF FUNCTION CHUNK"))
      {
        if (func_chunk_i >= 0) {
          if (func_chunk_i < func_chunk_cnt
            && IS(func_chunks[func_chunk_i].name, g_func))
          {
            // move on to next chunk
            ret = fseek(fasm, func_chunks[func_chunk_i].fptr, SEEK_SET);
            if (ret)
              aerr("seek failed for '%s' chunk #%d\n",
                g_func, func_chunk_i);
            func_chunk_i++;
          }
          else {
            if (func_chunk_ret == 0)
              aerr("no return from chunk?\n");
            fseek(fasm, func_chunk_ret, SEEK_SET);
            func_chunk_ret = 0;
            pending_endp = 1;
          }
        }
      }
      else if (p[2] == 'F' && IS_START(p, "; FUNCTION CHUNK AT ")) {
        func_chunks_used = 1;
        p += 20;
        if (IS_START(g_func, "sub_")) {
          unsigned long addr = strtoul(p, NULL, 16);
          unsigned long f_addr = strtoul(g_func + 4, NULL, 16);
          if (addr > f_addr)
            aerr("need a chunk %lX that is after %s\n", addr, g_func);
        }
      }
      continue;
    } // *p == ';'

parse_words:
    memset(words, 0, sizeof(words));
    for (wordc = 0; wordc < 16; wordc++) {
      p = sskip(next_word_s(words[wordc], sizeof(words[0]), p));
      if (*p == 0 || *p == ';') {
        wordc++;
        break;
      }
    }

    // alow asm patches in comments
    if (*p == ';' && IS_START(p, "; sctpatch:")) {
      p = sskip(p + 11);
      if (*p == 0 || *p == ';')
        continue;
      goto parse_words; // lame
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

do_pending_endp:
    // do delayed endp processing to collect switch jumptables
    if (pending_endp) {
      if (in_func && !skip_func && wordc >= 2
          && ((words[0][0] == 'd' && words[0][2] == 0)
              || (words[1][0] == 'd' && words[1][2] == 0)))
      {
        i = 1;
        if (words[1][0] == 'd' && words[1][2] == 0) {
          // label
          if (g_func_pd_cnt >= pd_alloc) {
            pd_alloc = pd_alloc * 2 + 16;
            g_func_pd = realloc(g_func_pd,
              sizeof(g_func_pd[0]) * pd_alloc);
            my_assert_not(g_func_pd, NULL);
          }
          pd = &g_func_pd[g_func_pd_cnt];
          g_func_pd_cnt++;
          memset(pd, 0, sizeof(*pd));
          strcpy(pd->label, words[0]);
          pd->type = OPT_CONST;
          pd->lmod = lmod_from_directive(words[1]);
          i = 2;
        }
        else {
          lmod = lmod_from_directive(words[0]);
          if (lmod != pd->lmod)
            aerr("lmod change? %d->%d\n", pd->lmod, lmod);
        }

        if (pd->count_alloc < pd->count + wordc) {
          pd->count_alloc = pd->count_alloc * 2 + 14 + wordc;
          pd->d = realloc(pd->d, sizeof(pd->d[0]) * pd->count_alloc);
          my_assert_not(pd->d, NULL);
        }
        for (; i < wordc; i++) {
          if (IS(words[i], "offset")) {
            pd->type = OPT_OFFSET;
            i++;
          }
          p = strchr(words[i], ',');
          if (p != NULL)
            *p = 0;
          if (pd->type == OPT_OFFSET)
            pd->d[pd->count].u.label = strdup(words[i]);
          else
            pd->d[pd->count].u.val = parse_number(words[i]);
          pd->d[pd->count].bt_i = -1;
          pd->count++;
        }
        continue;
      }

      if (in_func && !skip_func)
        gen_func(fout, g_fhdr, g_func, pi);

      pending_endp = 0;
      in_func = 0;
      g_ida_func_attr = 0;
      skip_warned = 0;
      skip_func = 0;
      g_func[0] = 0;
      func_chunks_used = 0;
      func_chunk_i = -1;
      if (pi != 0) {
        memset(&ops, 0, pi * sizeof(ops[0]));
        memset(g_labels, 0, pi * sizeof(g_labels[0]));
        pi = 0;
      }
      g_eqcnt = 0;
      for (i = 0; i < g_func_pd_cnt; i++) {
        pd = &g_func_pd[i];
        if (pd->type == OPT_OFFSET) {
          for (j = 0; j < pd->count; j++)
            free(pd->d[j].u.label);
        }
        free(pd->d);
        pd->d = NULL;
      }
      g_func_pd_cnt = 0;
      pd = NULL;
      if (wordc == 0)
        continue;
    }

    if (IS(words[1], "proc")) {
      if (in_func)
        aerr("proc '%s' while in_func '%s'?\n",
          words[0], g_func);
      p = words[0];
      if ((g_ida_func_attr & IDAFA_THUNK)
       || bsearch(&p, rlist, rlist_len, sizeof(rlist[0]), cmpstringp))
        skip_func = 1;
      strcpy(g_func, words[0]);
      set_label(0, words[0]);
      in_func = 1;
      continue;
    }

    if (IS(words[1], "endp"))
    {
      if (!in_func)
        aerr("endp '%s' while not in_func?\n", words[0]);
      if (!IS(g_func, words[0]))
        aerr("endp '%s' while in_func '%s'?\n",
          words[0], g_func);

      if (!skip_func && func_chunks_used) {
        // start processing chunks
        struct chunk_item *ci, key = { g_func, 0 };

        func_chunk_ret = ftell(fasm);
        if (!func_chunks_sorted) {
          qsort(func_chunks, func_chunk_cnt,
            sizeof(func_chunks[0]), cmp_chunks);
          func_chunks_sorted = 1;
        }
        ci = bsearch(&key, func_chunks, func_chunk_cnt,
               sizeof(func_chunks[0]), cmp_chunks);
        if (ci == NULL)
          aerr("'%s' needs chunks, but none found\n", g_func);
        func_chunk_i = ci - func_chunks;
        for (; func_chunk_i > 0; func_chunk_i--)
          if (!IS(func_chunks[func_chunk_i - 1].name, g_func))
            break;

        ret = fseek(fasm, func_chunks[func_chunk_i].fptr, SEEK_SET);
        if (ret)
          aerr("seek failed for '%s' chunk #%d\n", g_func, func_chunk_i);
        func_chunk_i++;
        continue;
      }
      pending_endp = 1;
      continue;
    }

    p = strchr(words[0], ':');
    if (p != NULL) {
      set_label(pi, words[0]);
      continue;
    }

    if (!in_func || skip_func) {
      if (!skip_warned && !skip_func && g_labels[pi][0] != 0) {
        if (verbose)
          anote("skipping from '%s'\n", g_labels[pi]);
        skip_warned = 1;
      }
      g_labels[pi][0] = 0;
      continue;
    }

    if (wordc > 1 && IS(words[1], "=")) {
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

    parse_op(&ops[pi], words, wordc);
    pi++;
  }

  fclose(fout);
  fclose(fasm);
  fclose(g_fhdr);

  return 0;
}

// vim:ts=2:shiftwidth=2:expandtab
