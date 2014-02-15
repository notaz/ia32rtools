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

#include "masm_tools.h"

enum op_flags {
  OPF_RMD    = (1 << 0), /* removed or optimized out */
  OPF_DATA   = (1 << 1), /* data processing - writes to dst opr */
  OPF_FLAGS  = (1 << 2), /* sets flags */
  OPF_JMP    = (1 << 3), /* branch, call */
  OPF_CJMP   = (1 << 4), /* cond. branch (cc or jecxz) */
  OPF_CC     = (1 << 5), /* uses flags */
  OPF_TAIL   = (1 << 6), /* ret or tail call */
  OPF_RSAVE  = (1 << 7), /* push/pop is local reg save/load */
  OPF_REP    = (1 << 8), /* prefixed by rep */
  OPF_REPZ   = (1 << 9), /* rep is repe/repz */
  OPF_REPNZ  = (1 << 10), /* rep is repne/repnz */
  OPF_FARG   = (1 << 11), /* push collected as func arg (no reuse) */
  OPF_EBP_S  = (1 << 12), /* ebp used as scratch here, not BP */
  OPF_DF     = (1 << 13), /* DF flag set */
  OPF_ATAIL  = (1 << 14), /* tail call with reused arg frame */
  OPF_32BIT  = (1 << 15), /* 32bit division */
};

enum op_op {
	OP_INVAL,
	OP_NOP,
	OP_PUSH,
	OP_POP,
	OP_LEAVE,
	OP_MOV,
	OP_LEA,
	OP_MOVZX,
	OP_MOVSX,
	OP_XCHG,
	OP_NOT,
	OP_CDQ,
	OP_STOS,
	OP_MOVS,
	OP_CMPS,
	OP_SCAS,
	OP_STD,
	OP_CLD,
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
	OP_RCL,
	OP_RCR,
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
	OP_JECXZ,
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

// must be sorted (larger len must be further in enum)
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
  unsigned int type_from_var:1; // .. in header, sometimes wrong
  unsigned int size_mismatch:1; // type override differs from C
  unsigned int size_lt:1;  // type override is larger than C
  unsigned int had_ds:1;   // had ds: prefix
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
  int argnum;             // push: altered before call arg #
  int cc_scratch;         // scratch storage during analysis
  int bt_i;               // branch target for branches
  struct parsed_data *btj;// branch targets for jumptables
  void *datap;
};

// datap:
// OP_CALL - parser proto hint (str), ptr to struct parsed_proto
// (OPF_CC) - point to one of (OPF_FLAGS) that affects cc op
// OP_POP - point to OP_PUSH in push/pop pair

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
static const struct parsed_proto *g_func_pp;
static struct parsed_data *g_func_pd;
static int g_func_pd_cnt;
static char g_func[256];
static char g_comment[256];
static int g_bp_frame;
static int g_sp_frame;
static int g_stack_frame_used;
static int g_stack_fsz;
static int g_ida_func_attr;
static int g_allow_regfunc;
#define ferr(op_, fmt, ...) do { \
  printf("error:%s:#%zd: '%s': " fmt, g_func, (op_) - ops, \
    dump_op(op_), ##__VA_ARGS__); \
  fcloseall(); \
  exit(1); \
} while (0)
#define fnote(op_, fmt, ...) \
  printf("error:%s:#%zd: '%s': " fmt, g_func, (op_) - ops, \
    dump_op(op_), ##__VA_ARGS__)

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
    "int", "_DWORD", "UINT_PTR", "DWORD",
    "WPARAM", "LPARAM", "UINT", "__int32",
    "LONG", "HIMC",
  };
  static const char *word_types[] = {
    "uint16_t", "int16_t", "_WORD",
    "unsigned __int16", "__int16",
  };
  static const char *byte_types[] = {
    "uint8_t", "int8_t", "char",
    "unsigned __int8", "__int8", "BYTE", "_BYTE",
    "CHAR", "_UNKNOWN",
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
  const struct parsed_proto *pp;
  enum opr_lenmod tmplmod;
  unsigned long number;
  char buf[256];
  int ret, len;
  int wordc_in;
  char *p;
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
      if (IS_START(label, "ds:")) {
        opr->had_ds = 1;
        label += 3;
      }
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
      p = strchr(words[w + 1], ')');
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

  if (IS_START(words[w], "ds:")) {
    opr->had_ds = 1;
    memmove(words[w], words[w] + 3, strlen(words[w]) - 2);
  }
  strcpy(opr->name, words[w]);

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
    p = strchr(words[w], '[');
    opr->type = OPT_REGMEM;
    parse_indmode(p, regmask_indirect, 0);
    strncpy(buf, words[w], p - words[w]);
    buf[p - words[w]] = 0;
    pp = proto_parse(g_fhdr, buf, 1);
    goto do_label;
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
  pp = proto_parse(g_fhdr, opr->name, 0);

do_label:
  if (pp != NULL) {
    if (pp->is_fptr || pp->is_func) {
      opr->lmod = OPLM_DWORD;
      opr->is_ptr = 1;
    }
    else {
      tmplmod = OPLM_UNSPEC;
      if (!guess_lmod_from_c_type(&tmplmod, &pp->type))
        anote("unhandled C type '%s' for '%s'\n",
          pp->type.name, opr->name);
      
      if (opr->lmod == OPLM_UNSPEC) {
        opr->lmod = tmplmod;
        opr->type_from_var = 1;
      }
      else if (opr->lmod != tmplmod) {
        opr->size_mismatch = 1;
        if (tmplmod < opr->lmod)
          opr->size_lt = 1;
      }
      opr->is_ptr = pp->type.is_ptr;
    }
    opr->is_array = pp->type.is_array;
  }

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

#define OPF_CJMP_CC (OPF_JMP|OPF_CJMP|OPF_CC)

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
  { "leave",OP_LEAVE,  0, 0, OPF_DATA },
  { "mov" , OP_MOV,    2, 2, OPF_DATA },
  { "lea",  OP_LEA,    2, 2, OPF_DATA },
  { "movzx",OP_MOVZX,  2, 2, OPF_DATA },
  { "movsx",OP_MOVSX,  2, 2, OPF_DATA },
  { "xchg", OP_XCHG,   2, 2, OPF_DATA },
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
  { "scasb",OP_SCAS,   0, 0, OPF_DATA|OPF_FLAGS },
  { "scasw",OP_SCAS,   0, 0, OPF_DATA|OPF_FLAGS },
  { "scasd",OP_SCAS,   0, 0, OPF_DATA|OPF_FLAGS },
  { "std",  OP_STD,    0, 0, OPF_DATA }, // special flag
  { "cld",  OP_CLD,    0, 0, OPF_DATA },
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
  { "rcl",  OP_RCL,    2, 2, OPF_DATA|OPF_FLAGS|OPF_CC },
  { "rcr",  OP_RCR,    2, 2, OPF_DATA|OPF_FLAGS|OPF_CC },
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
  { "retn", OP_RET,    0, 1, OPF_TAIL },
  { "call", OP_CALL,   1, 1, OPF_JMP|OPF_DATA|OPF_FLAGS },
  { "jmp",  OP_JMP,    1, 1, OPF_JMP },
  { "jecxz",OP_JECXZ,  1, 1, OPF_JMP|OPF_CJMP },
  { "jo",   OP_JO,     1, 1, OPF_CJMP_CC }, // 70 OF=1
  { "jno",  OP_JNO,    1, 1, OPF_CJMP_CC }, // 71 OF=0
  { "jc",   OP_JC,     1, 1, OPF_CJMP_CC }, // 72 CF=1
  { "jb",   OP_JC,     1, 1, OPF_CJMP_CC }, // 72
  { "jnc",  OP_JNC,    1, 1, OPF_CJMP_CC }, // 73 CF=0
  { "jnb",  OP_JNC,    1, 1, OPF_CJMP_CC }, // 73
  { "jae",  OP_JNC,    1, 1, OPF_CJMP_CC }, // 73
  { "jz",   OP_JZ,     1, 1, OPF_CJMP_CC }, // 74 ZF=1
  { "je",   OP_JZ,     1, 1, OPF_CJMP_CC }, // 74
  { "jnz",  OP_JNZ,    1, 1, OPF_CJMP_CC }, // 75 ZF=0
  { "jne",  OP_JNZ,    1, 1, OPF_CJMP_CC }, // 75
  { "jbe",  OP_JBE,    1, 1, OPF_CJMP_CC }, // 76 CF=1 || ZF=1
  { "jna",  OP_JBE,    1, 1, OPF_CJMP_CC }, // 76
  { "ja",   OP_JA,     1, 1, OPF_CJMP_CC }, // 77 CF=0 && ZF=0
  { "jnbe", OP_JA,     1, 1, OPF_CJMP_CC }, // 77
  { "js",   OP_JS,     1, 1, OPF_CJMP_CC }, // 78 SF=1
  { "jns",  OP_JNS,    1, 1, OPF_CJMP_CC }, // 79 SF=0
  { "jp",   OP_JP,     1, 1, OPF_CJMP_CC }, // 7a PF=1
  { "jpe",  OP_JP,     1, 1, OPF_CJMP_CC }, // 7a
  { "jnp",  OP_JNP,    1, 1, OPF_CJMP_CC }, // 7b PF=0
  { "jpo",  OP_JNP,    1, 1, OPF_CJMP_CC }, // 7b
  { "jl",   OP_JL,     1, 1, OPF_CJMP_CC }, // 7c SF!=OF
  { "jnge", OP_JL,     1, 1, OPF_CJMP_CC }, // 7c
  { "jge",  OP_JGE,    1, 1, OPF_CJMP_CC }, // 7d SF=OF
  { "jnl",  OP_JGE,    1, 1, OPF_CJMP_CC }, // 7d
  { "jle",  OP_JLE,    1, 1, OPF_CJMP_CC }, // 7e ZF=1 || SF!=OF
  { "jng",  OP_JLE,    1, 1, OPF_CJMP_CC }, // 7e
  { "jg",   OP_JG,     1, 1, OPF_CJMP_CC }, // 7f ZF=0 && SF=OF
  { "jnle", OP_JG,     1, 1, OPF_CJMP_CC }, // 7f
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
  case OP_SCAS:
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

  case OP_XCHG:
    op->regmask_src |= op->regmask_dst;
    op->regmask_dst |= op->regmask_src;
    break;

  case OP_JECXZ:
    op->operand_cnt = 1;
    op->regmask_src = 1 << xCX;
    op->operand[0].type = OPT_REG;
    op->operand[0].reg = xCX;
    op->operand[0].lmod = OPLM_DWORD;
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

  case OP_LEA:
    if (op->operand[0].type == OPT_REG
     && op->operand[1].type == OPT_REGMEM)
    {
      char buf[16];
      snprintf(buf, sizeof(buf), "%s+0", op->operand[0].name);
      if (IS(buf, op->operand[1].name))
        op->flags |= OPF_RMD;
    }
    break;

  case OP_CALL:
    // trashed regs must be explicitly detected later
    op->regmask_dst = 0;
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

// cast1 is the "final" cast
static const char *simplify_cast(const char *cast1, const char *cast2)
{
  static char buf[256];

  if (cast1[0] == 0)
    return cast2;
  if (cast2[0] == 0)
    return cast1;
  if (IS(cast1, cast2))
    return cast1;
  if (IS(cast1, "(s8)") && IS(cast2, "(u8)"))
    return cast1;
  if (IS(cast1, "(s16)") && IS(cast2, "(u16)"))
    return cast1;
  if (IS(cast1, "(u8)") && IS_START(cast2, "*(u8 *)"))
    return cast2;
  if (IS(cast1, "(u16)") && IS_START(cast2, "*(u16 *)"))
    return cast2;
  if (strchr(cast1, '*') && IS_START(cast2, "(u32)"))
    return cast1;

  snprintf(buf, sizeof(buf), "%s%s", cast1, cast2);
  return buf;
}

static const char *simplify_cast_num(const char *cast, unsigned int val)
{
  if (IS(cast, "(u8)") && val < 0x100)
    return "";
  if (IS(cast, "(s8)") && val < 0x80)
    return "";
  if (IS(cast, "(u16)") && val < 0x10000)
    return "";
  if (IS(cast, "(s16)") && val < 0x8000)
    return "";
  if (IS(cast, "(s32)") && val < 0x80000000)
    return "";

  return cast;
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

static int is_stack_access(struct parsed_op *po,
  const struct parsed_opr *popr)
{
  return (parse_stack_el(popr->name, NULL)
    || (g_bp_frame && !(po->flags & OPF_EBP_S)
        && IS_START(popr->name, "ebp")));
}

static void parse_stack_access(struct parsed_op *po,
  const char *name, char *ofs_reg, int *offset_out,
  int *stack_ra_out, const char **bp_arg_out)
{
  const char *bp_arg = "";
  const char *p = NULL;
  struct parsed_equ *eq;
  char *endp = NULL;
  int stack_ra = 0;
  int offset = 0;

  ofs_reg[0] = 0;

  if (IS_START(name, "ebp-")
   || (IS_START(name, "ebp+") && '0' <= name[4] && name[4] <= '9'))
  {
    p = name + 4;
    if (IS_START(p, "0x"))
      p += 2;
    offset = strtoul(p, &endp, 16);
    if (name[3] == '-')
      offset = -offset;
    if (*endp != 0)
      ferr(po, "ebp- parse of '%s' failed\n", name);
  }
  else {
    bp_arg = parse_stack_el(name, ofs_reg);
    snprintf(g_comment, sizeof(g_comment), "%s", bp_arg);
    eq = equ_find(po, bp_arg, &offset);
    if (eq == NULL)
      ferr(po, "detected but missing eq\n");
    offset += eq->offset;
  }

  if (!strncmp(name, "ebp", 3))
    stack_ra = 4;

  if (ofs_reg[0] == 0 && stack_ra <= offset && offset < stack_ra + 4)
    ferr(po, "reference to ra? %d %d\n", offset, stack_ra);

  *offset_out = offset;
  *stack_ra_out = stack_ra;
  if (bp_arg_out)
    *bp_arg_out = bp_arg;
}

static void stack_frame_access(struct parsed_op *po,
  struct parsed_opr *popr, char *buf, size_t buf_size,
  const char *name, const char *cast, int is_src, int is_lea)
{
  enum opr_lenmod tmp_lmod = OPLM_UNSPEC;
  const char *prefix = "";
  const char *bp_arg = NULL;
  char ofs_reg[16] = { 0, };
  int i, arg_i, arg_s;
  int unaligned = 0;
  int stack_ra = 0;
  int offset = 0;
  int sf_ofs;
  int lim;

  if (po->flags & OPF_EBP_S)
    ferr(po, "stack_frame_access while ebp is scratch\n");

  parse_stack_access(po, name, ofs_reg, &offset, &stack_ra, &bp_arg);

  if (offset > stack_ra)
  {
    arg_i = (offset - stack_ra - 4) / 4;
    if (arg_i < 0 || arg_i >= g_func_pp->argc_stack)
    {
      if (g_func_pp->is_vararg
          && arg_i == g_func_pp->argc_stack && is_lea)
      {
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

    for (i = arg_s = 0; i < g_func_pp->argc; i++) {
      if (g_func_pp->arg[i].reg != NULL)
        continue;
      if (arg_s == arg_i)
        break;
      arg_s++;
    }
    if (i == g_func_pp->argc)
      ferr(po, "arg %d not in prototype?\n", arg_i);

    popr->is_ptr = g_func_pp->arg[i].type.is_ptr;

    switch (popr->lmod)
    {
    case OPLM_BYTE:
      if (is_lea)
        ferr(po, "lea/byte to arg?\n");
      if (is_src && (offset & 3) == 0)
        snprintf(buf, buf_size, "%sa%d",
          simplify_cast(cast, "(u8)"), i + 1);
      else
        snprintf(buf, buf_size, "%sBYTE%d(a%d)",
          cast, offset & 3, i + 1);
      break;

    case OPLM_WORD:
      if (is_lea)
        ferr(po, "lea/word to arg?\n");
      if (offset & 1) {
        unaligned = 1;
        if (!is_src) {
          if (offset & 2)
            ferr(po, "problematic arg store\n");
          snprintf(buf, buf_size, "%s((char *)&a%d + 1)",
            simplify_cast(cast, "*(u16 *)"), i + 1);
        }
        else
          ferr(po, "unaligned arg word load\n");
      }
      else if (is_src && (offset & 2) == 0)
        snprintf(buf, buf_size, "%sa%d",
          simplify_cast(cast, "(u16)"), i + 1);
      else
        snprintf(buf, buf_size, "%s%sWORD(a%d)",
          cast, (offset & 2) ? "HI" : "LO", i + 1);
      break;

    case OPLM_DWORD:
      if (cast[0])
        prefix = cast;
      else if (is_src)
        prefix = "(u32)";

      if (offset & 3) {
        unaligned = 1;
        if (is_lea)
          snprintf(buf, buf_size, "(u32)&a%d + %d",
            i + 1, offset & 3);
        else if (!is_src)
          ferr(po, "unaligned arg store\n");
        else {
          // mov edx, [ebp+arg_4+2]; movsx ecx, dx
          snprintf(buf, buf_size, "%s(a%d >> %d)",
            prefix, i + 1, (offset & 3) * 8);
        }
      }
      else {
        snprintf(buf, buf_size, "%s%sa%d",
          prefix, is_lea ? "&" : "", i + 1);
      }
      break;

    default:
      ferr(po, "bp_arg bad lmod: %d\n", popr->lmod);
    }

    if (unaligned)
      snprintf(g_comment, sizeof(g_comment), "%s unaligned", bp_arg);

    // common problem
    guess_lmod_from_c_type(&tmp_lmod, &g_func_pp->arg[i].type);
    if (tmp_lmod != OPLM_DWORD
      && (unaligned || (!is_src && tmp_lmod < popr->lmod)))
    {
      ferr(po, "bp_arg arg%d/w offset %d and type '%s' is too small\n",
        i + 1, offset, g_func_pp->arg[i].type.name);
    }
    // can't check this because msvc likes to reuse
    // arg space for scratch..
    //if (popr->is_ptr && popr->lmod != OPLM_DWORD)
    //  ferr(po, "bp_arg arg%d: non-dword ptr access\n", i + 1);
  }
  else
  {
    if (g_stack_fsz == 0)
      ferr(po, "stack var access without stackframe\n");
    g_stack_frame_used = 1;

    sf_ofs = g_stack_fsz + offset;
    lim = (ofs_reg[0] != 0) ? -4 : 0;
    if (offset > 0 || sf_ofs < lim)
      ferr(po, "bp_stack offset %d/%d\n", offset, g_stack_fsz);

    if (is_lea)
      prefix = "(u32)&";
    else
      prefix = cast;

    switch (popr->lmod)
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
      ferr(po, "bp_stack bad lmod: %d\n", popr->lmod);
    }
  }
}

static void check_func_pp(struct parsed_op *po,
  const struct parsed_proto *pp, const char *pfx)
{
  char buf[256];

  if (pp->argc_reg != 0) {
    if (/*!g_allow_regfunc &&*/ !pp->is_fastcall) {
      pp_print(buf, sizeof(buf), pp);
      ferr(po, "%s: unexpected reg arg in icall: %s\n", pfx, buf);
    }
    if (pp->argc_stack > 0 && pp->argc_reg != 2)
      ferr(po, "%s: %d reg arg(s) with %d stack arg(s)\n",
        pfx, pp->argc_reg, pp->argc_stack);
  }
}

static const char *check_label_read_ref(struct parsed_op *po,
  const char *name)
{
  const struct parsed_proto *pp;

  pp = proto_parse(g_fhdr, name, 0);
  if (pp == NULL)
    ferr(po, "proto_parse failed for ref '%s'\n", name);

  if (pp->is_func)
    check_func_pp(po, pp, "ref");

  return pp->name;
}

static char *out_src_opr(char *buf, size_t buf_size,
  struct parsed_op *po, struct parsed_opr *popr, const char *cast,
  int is_lea)
{
  char tmp1[256], tmp2[256];
  char expr[256];
  const char *name;
  char *p;
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
      snprintf(buf, buf_size, "%s%s",
        simplify_cast(cast, "(u16)"), opr_reg_p(po, popr));
      break;
    case OPLM_BYTE:
      if (popr->name[1] == 'h') // XXX..
        snprintf(buf, buf_size, "%s(%s >> 8)",
          simplify_cast(cast, "(u8)"), opr_reg_p(po, popr));
      else
        snprintf(buf, buf_size, "%s%s",
          simplify_cast(cast, "(u8)"), opr_reg_p(po, popr));
      break;
    default:
      ferr(po, "invalid src lmod: %d\n", popr->lmod);
    }
    break;

  case OPT_REGMEM:
    if (is_stack_access(po, popr)) {
      stack_frame_access(po, popr, buf, buf_size,
        popr->name, cast, 1, is_lea);
      break;
    }

    strcpy(expr, popr->name);
    if (strchr(expr, '[')) {
      // special case: '[' can only be left for label[reg] form
      ret = sscanf(expr, "%[^[][%[^]]]", tmp1, tmp2);
      if (ret != 2)
        ferr(po, "parse failure for '%s'\n", expr);
      if (tmp1[0] == '(') {
        // (off_4FFF50+3)[eax]
        p = strchr(tmp1 + 1, ')');
        if (p == NULL || p[1] != 0)
          ferr(po, "parse failure (2) for '%s'\n", expr);
        *p = 0;
        memmove(tmp1, tmp1 + 1, strlen(tmp1));
      }
      snprintf(expr, sizeof(expr), "(u32)&%s + %s", tmp1, tmp2);
    }

    // XXX: do we need more parsing?
    if (is_lea) {
      snprintf(buf, buf_size, "%s", expr);
      break;
    }

    snprintf(buf, buf_size, "%s(%s)",
      simplify_cast(cast, lmod_cast_u_ptr(po, popr->lmod)), expr);
    break;

  case OPT_LABEL:
    name = check_label_read_ref(po, popr->name);
    if (cast[0] == 0 && popr->is_ptr)
      cast = "(u32)";

    if (is_lea)
      snprintf(buf, buf_size, "(u32)&%s", name);
    else if (popr->size_lt)
      snprintf(buf, buf_size, "%s%s%s%s", cast,
        lmod_cast_u_ptr(po, popr->lmod),
        popr->is_array ? "" : "&", name);
    else
      snprintf(buf, buf_size, "%s%s%s", cast, name,
        popr->is_array ? "[0]" : "");
    break;

  case OPT_OFFSET:
    name = check_label_read_ref(po, popr->name);
    if (cast[0] == 0)
      cast = "(u32)";
    if (is_lea)
      ferr(po, "lea an offset?\n");
    snprintf(buf, buf_size, "%s&%s", cast, name);
    break;

  case OPT_CONST:
    if (is_lea)
      ferr(po, "lea from const?\n");

    printf_number(tmp1, sizeof(tmp1), popr->val);
    if (popr->val == 0 && strchr(cast, '*'))
      snprintf(buf, buf_size, "NULL");
    else
      snprintf(buf, buf_size, "%s%s",
        simplify_cast_num(cast, popr->val), tmp1);
    break;

  default:
    ferr(po, "invalid src type: %d\n", popr->type);
  }

  return buf;
}

// note: may set is_ptr (we find that out late for ebp frame..)
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
    if (is_stack_access(po, popr)) {
      stack_frame_access(po, popr, buf, buf_size,
        popr->name, "", 0, 0);
      break;
    }

    return out_src_opr(buf, buf_size, po, popr, NULL, 0);

  case OPT_LABEL:
    if (popr->size_mismatch)
      snprintf(buf, buf_size, "%s%s%s",
        lmod_cast_u_ptr(po, popr->lmod),
        popr->is_array ? "" : "&", popr->name);
    else
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

  case OP_RCL:
  case OP_RCR:
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
  struct parsed_op *po, enum parsed_flag_op pfo, int is_inv)
{
  const char *cast, *scast, *cast_use;
  char buf1[256], buf2[256];
  enum opr_lenmod lmod;

  if (po->operand[0].lmod != po->operand[1].lmod)
    ferr(po, "%s: lmod mismatch: %d %d\n", __func__,
      po->operand[0].lmod, po->operand[1].lmod);
  lmod = po->operand[0].lmod;

  cast = lmod_cast_u(po, lmod);
  scast = lmod_cast_s(po, lmod);

  switch (pfo) {
  case PFO_C:
  case PFO_Z:
  case PFO_BE: // !a
    cast_use = cast;
    break;

  case PFO_S:
  case PFO_L: // !ge
  case PFO_LE:
    cast_use = scast;
    break;

  default:
    ferr(po, "%s: unhandled parsed_flag_op: %d\n", __func__, pfo);
  }

  out_src_opr(buf1, sizeof(buf1), po, &po->operand[0], cast_use, 0);
  out_src_opr(buf2, sizeof(buf2), po, &po->operand[1], cast_use, 0);

  switch (pfo) {
  case PFO_C:
    // note: must be unsigned compare
    snprintf(buf, buf_size, "(%s %s %s)",
      buf1, is_inv ? ">=" : "<", buf2);
    break;

  case PFO_Z:
    snprintf(buf, buf_size, "(%s %s %s)",
      buf1, is_inv ? "!=" : "==", buf2);
    break;

  case PFO_BE: // !a
    // note: must be unsigned compare
    snprintf(buf, buf_size, "(%s %s %s)",
      buf1, is_inv ? ">" : "<=", buf2);

    // annoying case
    if (is_inv && lmod == OPLM_BYTE
      && po->operand[1].type == OPT_CONST
      && po->operand[1].val == 0xff)
    {
      snprintf(g_comment, sizeof(g_comment), "if %s", buf);
      snprintf(buf, buf_size, "(0)");
    }
    break;

  // note: must be signed compare
  case PFO_S:
    snprintf(buf, buf_size, "(%s(%s - %s) %s 0)",
      scast, buf1, buf2, is_inv ? ">=" : "<");
    break;

  case PFO_L: // !ge
    snprintf(buf, buf_size, "(%s %s %s)",
      buf1, is_inv ? ">=" : "<", buf2);
    break;

  case PFO_LE:
    snprintf(buf, buf_size, "(%s %s %s)",
      buf1, is_inv ? ">" : "<=", buf2);
    break;

  default:
    break;
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
    out_cmp_for_cc(buf, buf_size, po, pfo, is_inv);
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
  else if (popr1->lmod != popr2->lmod) {
    if (popr1->type_from_var) {
      popr1->size_mismatch = 1;
      if (popr1->lmod < popr2->lmod)
        popr1->size_lt = 1;
      popr1->lmod = popr2->lmod;
    }
    else if (popr2->type_from_var) {
      popr2->size_mismatch = 1;
      if (popr2->lmod < popr1->lmod)
        popr2->size_lt = 1;
      popr2->lmod = popr1->lmod;
    }
    else
      ferr(po, "conflicting lmods: %d vs %d\n",
        popr1->lmod, popr2->lmod);
  }
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

static void op_set_clear_flag(struct parsed_op *po,
  enum op_flags flag_set, enum op_flags flag_clear)
{
  po->flags |= flag_set;
  po->flags &= ~flag_clear;
}

// last op in stream - unconditional branch or ret
#define LAST_OP(_i) ((ops[_i].flags & OPF_TAIL) \
  || (ops[_i].flags & (OPF_JMP|OPF_CJMP)) == OPF_JMP)

static int scan_for_pop(int i, int opcnt, const char *reg,
  int magic, int depth, int *maxdepth, int do_flags)
{
  const struct parsed_proto *pp;
  struct parsed_op *po;
  int ret = 0;
  int j;

  for (; i < opcnt; i++) {
    po = &ops[i];
    if (po->cc_scratch == magic)
      break; // already checked
    po->cc_scratch = magic;

    if (po->flags & OPF_TAIL) {
      if (po->op == OP_CALL) {
        pp = proto_parse(g_fhdr, po->operand[0].name, 0);
        if (pp != NULL && pp->is_noreturn)
          // no stack cleanup for noreturn
          return ret;
      }
      return -1; // deadend
    }

    if ((po->flags & OPF_RMD)
        || (po->op == OP_PUSH && po->argnum != 0)) // arg push
      continue;

    if ((po->flags & OPF_JMP) && po->op != OP_CALL) {
      if (po->btj != NULL) {
        // jumptable
        for (j = 0; j < po->btj->count; j++) {
          ret |= scan_for_pop(po->btj->d[j].bt_i, opcnt, reg, magic,
                   depth, maxdepth, do_flags);
          if (ret < 0)
            return ret; // dead end
        }
        return ret;
      }

      if (po->bt_i < 0) {
        ferr(po, "dead branch\n");
        return -1;
      }

      if (po->flags & OPF_CJMP) {
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
      if (po->op == OP_PUSH && !(po->flags & OPF_FARG)) {
        depth++;
        if (depth > *maxdepth)
          *maxdepth = depth;
        if (do_flags)
          op_set_clear_flag(po, OPF_RSAVE, OPF_RMD);
      }
      else if (po->op == OP_POP) {
        if (depth == 0) {
          if (do_flags)
            op_set_clear_flag(po, OPF_RMD, OPF_RSAVE);
          return 1;
        }
        else {
          depth--;
          if (depth < 0) // should not happen
            ferr(po, "fail with depth\n");
          if (do_flags)
            op_set_clear_flag(po, OPF_RSAVE, OPF_RMD);
        }
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

static void scan_propagate_df(int i, int opcnt)
{
  struct parsed_op *po = &ops[i];
  int j;

  for (; i < opcnt; i++) {
    po = &ops[i];
    if (po->flags & OPF_DF)
      return; // already resolved
    po->flags |= OPF_DF;

    if (po->op == OP_CALL)
      ferr(po, "call with DF set?\n");

    if (po->flags & OPF_JMP) {
      if (po->btj != NULL) {
        // jumptable
        for (j = 0; j < po->btj->count; j++)
          scan_propagate_df(po->btj->d[j].bt_i, opcnt);
        return;
      }

      if (po->bt_i < 0) {
        ferr(po, "dead branch\n");
        return;
      }

      if (po->flags & OPF_CJMP)
        scan_propagate_df(po->bt_i, opcnt);
      else
        i = po->bt_i - 1;
      continue;
    }

    if (po->flags & OPF_TAIL)
      break;

    if (po->op == OP_CLD) {
      po->flags |= OPF_RMD;
      return;
    }
  }

  ferr(po, "missing DF clear?\n");
}

// is operand 'opr' modified by parsed_op 'po'?
static int is_opr_modified(const struct parsed_opr *opr,
  const struct parsed_op *po)
{
  int mask;

  if ((po->flags & OPF_RMD) || !(po->flags & OPF_DATA))
    return 0;

  if (opr->type == OPT_REG) {
    if (po->op == OP_CALL) {
      mask = (1 << xAX) | (1 << xCX) | (1 << xDX);
      if ((1 << opr->reg) & mask)
        return 1;
      else
        return 0;
    }

    if (po->operand[0].type == OPT_REG) {
      if (po->regmask_dst & (1 << opr->reg))
        return 1;
      else
        return 0;
    }
  }

  return IS(po->operand[0].name, opr->name);
}

// is any operand of parsed_op 'po_test' modified by parsed_op 'po'?
static int is_any_opr_modified(const struct parsed_op *po_test,
  const struct parsed_op *po, int c_mode)
{
  int mask;
  int i;

  if ((po->flags & OPF_RMD) || !(po->flags & OPF_DATA))
    return 0;

  if (po_test->operand_cnt == 1 && po_test->operand[0].type == OPT_CONST)
    return 0;

  if ((po_test->regmask_src | po_test->regmask_dst) & po->regmask_dst)
    return 1;

  // in reality, it can wreck any register, but in decompiled C
  // version it can only overwrite eax or edx:eax
  mask = (1 << xAX) | (1 << xDX);
  if (!c_mode)
    mask |= 1 << xCX;

  if (po->op == OP_CALL
   && ((po_test->regmask_src | po_test->regmask_dst) & mask))
    return 1;

  for (i = 0; i < po_test->operand_cnt; i++)
    if (IS(po_test->operand[i].name, po->operand[0].name))
      return 1;

  return 0;
}

// scan for any po_test operand modification in range given
static int scan_for_mod(struct parsed_op *po_test, int i, int opcnt,
  int c_mode)
{
  if (po_test->operand_cnt == 1 && po_test->operand[0].type == OPT_CONST)
    return -1;

  for (; i < opcnt; i++) {
    if (is_any_opr_modified(po_test, &ops[i], c_mode))
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

static int scan_for_flag_set(int i, int magic, int *branched,
  int *setters, int *setter_cnt)
{
  struct label_ref *lr;
  int ret;

  while (i >= 0) {
    if (ops[i].cc_scratch == magic) {
      ferr(&ops[i], "%s looped\n", __func__);
      return -1;
    }
    ops[i].cc_scratch = magic;

    if (g_labels[i][0] != 0) {
      *branched = 1;

      lr = &g_label_refs[i];
      for (; lr->next; lr = lr->next) {
        ret = scan_for_flag_set(lr->i, magic,
                branched, setters, setter_cnt);
        if (ret < 0)
          return ret;
      }

      if (i > 0 && LAST_OP(i - 1)) {
        i = lr->i;
        continue;
      }
      ret = scan_for_flag_set(lr->i, magic,
              branched, setters, setter_cnt);
      if (ret < 0)
        return ret;
    }
    i--;

    if (ops[i].flags & OPF_FLAGS) {
      setters[*setter_cnt] = i;
      (*setter_cnt)++;
      return 0;
    }

    if ((ops[i].flags & (OPF_JMP|OPF_CJMP)) == OPF_JMP)
      return -1;
  }

  return -1;
}

// scan back for cdq, if anything modifies edx, fail
static int scan_for_cdq_edx(int i)
{
  while (i >= 0) {
    if (g_labels[i][0] != 0) {
      if (g_label_refs[i].next != NULL)
        return -1;
      if (i > 0 && LAST_OP(i - 1)) {
        i = g_label_refs[i].i;
        continue;
      }
      return -1;
    }
    i--;

    if (ops[i].op == OP_CDQ)
      return i;

    if (ops[i].regmask_dst & (1 << xDX))
      return -1;
  }

  return -1;
}

static int scan_for_reg_clear(int i, int reg)
{
  while (i >= 0) {
    if (g_labels[i][0] != 0) {
      if (g_label_refs[i].next != NULL)
        return -1;
      if (i > 0 && LAST_OP(i - 1)) {
        i = g_label_refs[i].i;
        continue;
      }
      return -1;
    }
    i--;

    if (ops[i].op == OP_XOR
     && ops[i].operand[0].lmod == OPLM_DWORD
     && ops[i].operand[0].reg == ops[i].operand[1].reg
     && ops[i].operand[0].reg == reg)
      return i;

    if (ops[i].regmask_dst & (1 << reg))
      return -1;
  }

  return -1;
}

// scan for positive, constant esp adjust
static int scan_for_esp_adjust(int i, int opcnt, int *adj,
  int *multipath)
{
  const struct parsed_proto *pp;
  struct parsed_op *po;
  int first_pop = -1;

  *adj = *multipath = 0;

  for (; i < opcnt; i++) {
    po = &ops[i];

    if (g_labels[i][0] != 0)
      *multipath = 1;

    if (po->op == OP_ADD && po->operand[0].reg == xSP) {
      if (po->operand[1].type != OPT_CONST)
        ferr(&ops[i], "non-const esp adjust?\n");
      *adj += po->operand[1].val;
      if (*adj & 3)
        ferr(&ops[i], "unaligned esp adjust: %x\n", *adj);
      return i;
    }
    else if (po->op == OP_PUSH && !(po->flags & OPF_RMD)) {
      //if (first_pop == -1)
      //  first_pop = -2; // none
      *adj -= lmod_bytes(po, po->operand[0].lmod);
    }
    else if (po->op == OP_POP && !(po->flags & OPF_RMD)) {
      // seems like msvc only uses 'pop ecx' for stack realignment..
      if (po->operand[0].type != OPT_REG || po->operand[0].reg != xCX)
        break;
      if (first_pop == -1 && *adj >= 0)
        first_pop = i;
      *adj += lmod_bytes(po, po->operand[0].lmod);
    }
    else if (po->flags & (OPF_JMP|OPF_TAIL)) {
      if (po->op == OP_JMP && po->btj == NULL) {
        i = po->bt_i - 1;
        continue;
      }
      if (po->op != OP_CALL)
        break;
      if (po->operand[0].type != OPT_LABEL)
        break;
      pp = po->datap;
      if (pp != NULL && pp->is_stdcall)
        break;
    }
  }

  if (first_pop >= 0) {
    // probably 'pop ecx' was used..
    return first_pop;
  }

  return -1;
}

static void scan_fwd_set_flags(int i, int opcnt, int magic, int flags)
{
  struct parsed_op *po;
  int j;

  if (i < 0)
    ferr(ops, "%s: followed bad branch?\n", __func__);

  for (; i < opcnt; i++) {
    po = &ops[i];
    if (po->cc_scratch == magic)
      return;
    po->cc_scratch = magic;
    po->flags |= flags;

    if ((po->flags & OPF_JMP) && po->op != OP_CALL) {
      if (po->btj != NULL) {
        // jumptable
        for (j = 0; j < po->btj->count; j++)
          scan_fwd_set_flags(po->btj->d[j].bt_i, opcnt, magic, flags);
        return;
      }

      scan_fwd_set_flags(po->bt_i, opcnt, magic, flags);
      if (!(po->flags & OPF_CJMP))
        return;
    }
    if (po->flags & OPF_TAIL)
      return;
  }
}

static const struct parsed_proto *try_recover_pp(
  struct parsed_op *po, const struct parsed_opr *opr, int *search_instead)
{
  const struct parsed_proto *pp = NULL;
  char buf[256];
  char *p;

  // maybe an arg of g_func?
  if (opr->type == OPT_REGMEM && is_stack_access(po, opr))
  {
    char ofs_reg[16] = { 0, };
    int arg, arg_s, arg_i;
    int stack_ra = 0;
    int offset = 0;

    parse_stack_access(po, opr->name, ofs_reg,
      &offset, &stack_ra, NULL);
    if (ofs_reg[0] != 0)
      ferr(po, "offset reg on arg access?\n");
    if (offset <= stack_ra) {
      // search who set the stack var instead
      if (search_instead != NULL)
        *search_instead = 1;
      return NULL;
    }

    arg_i = (offset - stack_ra - 4) / 4;
    for (arg = arg_s = 0; arg < g_func_pp->argc; arg++) {
      if (g_func_pp->arg[arg].reg != NULL)
        continue;
      if (arg_s == arg_i)
        break;
      arg_s++;
    }
    if (arg == g_func_pp->argc)
      ferr(po, "stack arg %d not in prototype?\n", arg_i);

    pp = g_func_pp->arg[arg].fptr;
    if (pp == NULL)
      ferr(po, "icall sa: arg%d is not a fptr?\n", arg + 1);
    check_func_pp(po, pp, "icall arg");
  }
  else if (opr->type == OPT_REGMEM && strchr(opr->name + 1, '[')) {
    // label[index]
    p = strchr(opr->name + 1, '[');
    memcpy(buf, opr->name, p - opr->name);
    buf[p - opr->name] = 0;
    pp = proto_parse(g_fhdr, buf, 0);
  }
  else if (opr->type == OPT_OFFSET || opr->type == OPT_LABEL) {
    pp = proto_parse(g_fhdr, opr->name, 0);
    if (pp == NULL)
      ferr(po, "proto_parse failed for icall from '%s'\n", opr->name);
    check_func_pp(po, pp, "reg-fptr ref");
  }

  return pp;
}

static void scan_for_call_type(int i, const struct parsed_opr *opr,
  int magic, const struct parsed_proto **pp_found, int *multi)
{
  const struct parsed_proto *pp = NULL;
  struct parsed_op *po;
  struct label_ref *lr;

  while (i >= 0) {
    if (ops[i].cc_scratch == magic)
      return;
    ops[i].cc_scratch = magic;

    if (g_labels[i][0] != 0) {
      lr = &g_label_refs[i];
      for (; lr != NULL; lr = lr->next)
        scan_for_call_type(lr->i, opr, magic, pp_found, multi);
      if (i > 0 && LAST_OP(i - 1))
        return;
    }
    i--;

    if (!(ops[i].flags & OPF_DATA))
      continue;
    if (!is_opr_modified(opr, &ops[i]))
      continue;
    if (ops[i].op != OP_MOV && ops[i].op != OP_LEA) {
      // most probably trashed by some processing
      *pp_found = NULL;
      return;
    }

    opr = &ops[i].operand[1];
    if (opr->type != OPT_REG)
      break;
  }

  po = (i >= 0) ? &ops[i] : ops;

  if (i < 0) {
    // reached the top - can only be an arg-reg
    if (opr->type != OPT_REG)
      return;

    for (i = 0; i < g_func_pp->argc; i++) {
      if (g_func_pp->arg[i].reg == NULL)
        continue;
      if (IS(opr->name, g_func_pp->arg[i].reg))
        break;
    }
    if (i == g_func_pp->argc)
      return;
    pp = g_func_pp->arg[i].fptr;
    if (pp == NULL)
      ferr(po, "icall: arg%d (%s) is not a fptr?\n",
        i + 1, g_func_pp->arg[i].reg);
    check_func_pp(po, pp, "icall reg-arg");
  }
  else
    pp = try_recover_pp(po, opr, NULL);

  if (*pp_found != NULL && pp != NULL && *pp_found != pp) {
    if (!IS((*pp_found)->ret_type.name, pp->ret_type.name)
      || (*pp_found)->is_stdcall != pp->is_stdcall
      || (*pp_found)->is_fptr != pp->is_fptr
      || (*pp_found)->argc != pp->argc
      || (*pp_found)->argc_reg != pp->argc_reg
      || (*pp_found)->argc_stack != pp->argc_stack)
    {
      ferr(po, "icall: parsed_proto mismatch\n");
    }
    *multi = 1;
  }
  if (pp != NULL)
    *pp_found = pp;
}

static const struct parsed_proto *resolve_icall(int i, int opcnt,
  int *multi_src)
{
  const struct parsed_proto *pp = NULL;
  int search_advice = 0;

  *multi_src = 0;

  switch (ops[i].operand[0].type) {
  case OPT_REGMEM:
  case OPT_LABEL:
  case OPT_OFFSET:
    pp = try_recover_pp(&ops[i], &ops[i].operand[0], &search_advice);
    if (!search_advice)
      break;
    // fallthrough
  default:
    scan_for_call_type(i, &ops[i].operand[0], i + opcnt * 9, &pp,
      multi_src);
    break;
  }

  return pp;
}

static int collect_call_args_r(struct parsed_op *po, int i,
  struct parsed_proto *pp, int *regmask, int *save_arg_vars, int arg,
  int magic, int need_op_saving, int may_reuse)
{
  struct parsed_proto *pp_tmp;
  struct label_ref *lr;
  int need_to_save_current;
  int ret = 0;
  int j;

  if (i < 0) {
    ferr(po, "dead label encountered\n");
    return -1;
  }

  for (; arg < pp->argc; arg++)
    if (pp->arg[arg].reg == NULL)
      break;
  magic = (magic & 0xffffff) | (arg << 24);

  for (j = i; j >= 0 && (arg < pp->argc || pp->is_unresolved); )
  {
    if (((ops[j].cc_scratch ^ magic) & 0xffffff) == 0) {
      if (ops[j].cc_scratch != magic) {
        ferr(&ops[j], "arg collect hit same path with diff args for %s\n",
           pp->name);
        return -1;
      }
      // ok: have already been here
      return 0;
    }
    ops[j].cc_scratch = magic;

    if (g_labels[j][0] != 0 && g_label_refs[j].i != -1) {
      lr = &g_label_refs[j];
      if (lr->next != NULL)
        need_op_saving = 1;
      for (; lr->next; lr = lr->next) {
        if ((ops[lr->i].flags & (OPF_JMP|OPF_CJMP)) != OPF_JMP)
          may_reuse = 1;
        ret = collect_call_args_r(po, lr->i, pp, regmask, save_arg_vars,
                arg, magic, need_op_saving, may_reuse);
        if (ret < 0)
          return ret;
      }

      if ((ops[lr->i].flags & (OPF_JMP|OPF_CJMP)) != OPF_JMP)
        may_reuse = 1;
      if (j > 0 && LAST_OP(j - 1)) {
        // follow last branch in reverse
        j = lr->i;
        continue;
      }
      need_op_saving = 1;
      ret = collect_call_args_r(po, lr->i, pp, regmask, save_arg_vars,
               arg, magic, need_op_saving, may_reuse);
      if (ret < 0)
        return ret;
    }
    j--;

    if (ops[j].op == OP_CALL)
    {
      if (pp->is_unresolved)
        break;

      pp_tmp = ops[j].datap;
      if (pp_tmp == NULL)
        ferr(po, "arg collect hit unparsed call '%s'\n",
          ops[j].operand[0].name);
      if (may_reuse && pp_tmp->argc_stack > 0)
        ferr(po, "arg collect %d/%d hit '%s' with %d stack args\n",
          arg, pp->argc, opr_name(&ops[j], 0), pp_tmp->argc_stack);
    }
    else if (ops[j].op == OP_ADD && ops[j].operand[0].reg == xSP) {
      if (pp->is_unresolved)
        break;

      ferr(po, "arg collect %d/%d hit esp adjust\n",
        arg, pp->argc);
    }
    else if (ops[j].op == OP_POP) {
      if (pp->is_unresolved)
        break;

      ferr(po, "arg collect %d/%d hit pop\n", arg, pp->argc);
    }
    else if (ops[j].flags & OPF_CJMP)
    {
      if (pp->is_unresolved)
        break;

      may_reuse = 1;
    }
    else if (ops[j].op == OP_PUSH && !(ops[j].flags & OPF_FARG))
    {
      if (pp->is_unresolved && (ops[j].flags & OPF_RMD))
        break;

      pp->arg[arg].datap = &ops[j];
      need_to_save_current = 0;
      if (!need_op_saving) {
        ret = scan_for_mod(&ops[j], j + 1, i, 1);
        need_to_save_current = (ret >= 0);
      }
      if (need_op_saving || need_to_save_current) {
        // mark this push as one that needs operand saving
        ops[j].flags &= ~OPF_RMD;
        if (ops[j].argnum == 0) {
          ops[j].argnum = arg + 1;
          *save_arg_vars |= 1 << arg;
        }
        else if (ops[j].argnum < arg + 1)
          ferr(&ops[j], "argnum conflict (%d<%d) for '%s'\n",
            ops[j].argnum, arg + 1, pp->name);
      }
      else if (ops[j].argnum == 0)
        ops[j].flags |= OPF_RMD;

      // some PUSHes are reused by different calls on other branches,
      // but that can't happen if we didn't branch, so they
      // can be removed from future searches (handles nested calls)
      if (!may_reuse)
        ops[j].flags |= OPF_FARG;

      ops[j].flags &= ~OPF_RSAVE;

      arg++;
      if (!pp->is_unresolved) {
        // next arg
        for (; arg < pp->argc; arg++)
          if (pp->arg[arg].reg == NULL)
            break;
      }
      magic = (magic & 0xffffff) | (arg << 24);

      // tracking reg usage
      if (ops[j].operand[0].type == OPT_REG)
        *regmask |= 1 << ops[j].operand[0].reg;
    }
  }

  if (arg < pp->argc) {
    ferr(po, "arg collect failed for '%s': %d/%d\n",
      pp->name, arg, pp->argc);
    return -1;
  }

  return arg;
}

static int collect_call_args(struct parsed_op *po, int i,
  struct parsed_proto *pp, int *regmask, int *save_arg_vars,
  int magic)
{
  int ret;
  int a;

  ret = collect_call_args_r(po, i, pp, regmask, save_arg_vars,
          0, magic, 0, 0);
  if (ret < 0)
    return ret;

  if (pp->is_unresolved) {
    pp->argc += ret;
    pp->argc_stack += ret;
    for (a = 0; a < pp->argc; a++)
      if (pp->arg[a].type.name == NULL)
        pp->arg[a].type.name = strdup("int");
  }

  return ret;
}

static void pp_insert_reg_arg(struct parsed_proto *pp, const char *reg)
{
  int i;

  for (i = 0; i < pp->argc; i++)
    if (pp->arg[i].reg == NULL)
      break;

  if (pp->argc_stack)
    memmove(&pp->arg[i + 1], &pp->arg[i],
      sizeof(pp->arg[0]) * pp->argc_stack);
  memset(&pp->arg[i], 0, sizeof(pp->arg[i]));
  pp->arg[i].reg = strdup(reg);
  pp->arg[i].type.name = strdup("int");
  pp->argc++;
  pp->argc_reg++;
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
  lr_new->next = lr->next;
  lr->next = lr_new;
}

static void output_std_flags(FILE *fout, struct parsed_op *po,
  int *pfomask, const char *dst_opr_text)
{
  if (*pfomask & (1 << PFO_Z)) {
    fprintf(fout, "\n  cond_z = (%s%s == 0);",
      lmod_cast_u(po, po->operand[0].lmod), dst_opr_text);
    *pfomask &= ~(1 << PFO_Z);
  }
  if (*pfomask & (1 << PFO_S)) {
    fprintf(fout, "\n  cond_s = (%s%s < 0);",
      lmod_cast_s(po, po->operand[0].lmod), dst_opr_text);
    *pfomask &= ~(1 << PFO_S);
  }
}

static void output_pp_attrs(FILE *fout, const struct parsed_proto *pp,
  int is_noreturn)
{
  if (pp->is_fastcall)
    fprintf(fout, "__fastcall ");
  else if (pp->is_stdcall && pp->argc_reg == 0)
    fprintf(fout, "__stdcall ");
  if (pp->is_noreturn || is_noreturn)
    fprintf(fout, "noreturn ");
}

static void gen_func(FILE *fout, FILE *fhdr, const char *funcn, int opcnt)
{
  struct parsed_op *po, *delayed_flag_op = NULL, *tmp_op;
  struct parsed_opr *last_arith_dst = NULL;
  char buf1[256], buf2[256], buf3[256], cast[64];
  const struct parsed_proto *pp_c;
  struct parsed_proto *pp, *pp_tmp;
  struct parsed_data *pd;
  const char *tmpname;
  enum parsed_flag_op pfo;
  int save_arg_vars = 0;
  int cond_vars = 0;
  int need_tmp_var = 0;
  int need_tmp64 = 0;
  int had_decl = 0;
  int label_pending = 0;
  int regmask_save = 0;
  int regmask_arg = 0;
  int regmask_now = 0;
  int regmask_init = 0;
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
  g_stack_frame_used = 0;

  g_func_pp = proto_parse(fhdr, funcn, 0);
  if (g_func_pp == NULL)
    ferr(ops, "proto_parse failed for '%s'\n", funcn);

  fprintf(fout, "%s ", g_func_pp->ret_type.name);
  output_pp_attrs(fout, g_func_pp, g_ida_func_attr & IDAFA_NORETURN);
  fprintf(fout, "%s(", g_func_pp->name);

  for (i = 0; i < g_func_pp->argc; i++) {
    if (i > 0)
      fprintf(fout, ", ");
    if (g_func_pp->arg[i].fptr != NULL) {
      // func pointer..
      pp = g_func_pp->arg[i].fptr;
      fprintf(fout, "%s (", pp->ret_type.name);
      output_pp_attrs(fout, pp, 0);
      fprintf(fout, "*a%d)(", i + 1);
      for (j = 0; j < pp->argc; j++) {
        if (j > 0)
          fprintf(fout, ", ");
        if (pp->arg[j].fptr)
          ferr(ops, "nested fptr\n");
        fprintf(fout, "%s", pp->arg[j].type.name);
      }
      if (pp->is_vararg) {
        if (j > 0)
          fprintf(fout, ", ");
        fprintf(fout, "...");
      }
      fprintf(fout, ")");
    }
    else {
      fprintf(fout, "%s a%d", g_func_pp->arg[i].type.name, i + 1);
    }
    if (g_func_pp->arg[i].reg != NULL) {
      reg = char_array_i(regs_r32,
              ARRAY_SIZE(regs_r32), g_func_pp->arg[i].reg);
      if (reg < 0)
        ferr(ops, "arg '%s' is not a reg?\n", g_func_pp->arg[i].reg);
      regmask_arg |= 1 << reg;
    }
  }
  if (g_func_pp->is_vararg) {
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
      j = i - 1;
      if (i == opcnt && (ops[j].flags & OPF_JMP)) {
        if (found) {
          if (ops[j].op == OP_JMP && !ops[j].operand[0].had_ds)
            // probably local branch back..
            break;
          if (ops[j].op == OP_CALL)
            // probably noreturn call..
            break;
        }
        j--;
      }

      if ((ops[j].op == OP_POP && IS(opr_name(&ops[j], 0), "ebp"))
          || ops[j].op == OP_LEAVE)
      {
        ops[j].flags |= OPF_RMD;
      }
      else if (!(g_ida_func_attr & IDAFA_NORETURN))
        ferr(&ops[j], "'pop ebp' expected\n");

      if (g_stack_fsz != 0) {
        if (ops[j - 1].op == OP_MOV
            && IS(opr_name(&ops[j - 1], 0), "esp")
            && IS(opr_name(&ops[j - 1], 1), "ebp"))
        {
          ops[j - 1].flags |= OPF_RMD;
        }
        else if (ops[j].op != OP_LEAVE
          && !(g_ida_func_attr & IDAFA_NORETURN))
        {
          ferr(&ops[j - 1], "esp restore expected\n");
        }

        if (ecx_push && ops[j - 2].op == OP_POP
          && IS(opr_name(&ops[j - 2], 0), "ecx"))
        {
          ferr(&ops[j - 2], "unexpected ecx pop\n");
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
  // - parse calls with labels
  // - resolve all branches
  for (i = 0; i < opcnt; i++)
  {
    po = &ops[i];
    po->bt_i = -1;
    po->btj = NULL;

    if (po->flags & OPF_RMD)
      continue;

    if (po->op == OP_CALL) {
      pp = NULL;

      if (po->operand[0].type == OPT_LABEL) {
        tmpname = opr_name(po, 0);
        if (IS_START(tmpname, "loc_"))
          ferr(po, "call to loc_*\n");
        pp_c = proto_parse(fhdr, tmpname, 0);
        if (pp_c == NULL)
          ferr(po, "proto_parse failed for call '%s'\n", tmpname);

        pp = proto_clone(pp_c);
        my_assert_not(pp, NULL);
      }
      else if (po->datap != NULL) {
        pp = calloc(1, sizeof(*pp));
        my_assert_not(pp, NULL);

        ret = parse_protostr(po->datap, pp);
        if (ret < 0)
          ferr(po, "bad protostr supplied: %s\n", (char *)po->datap);
        free(po->datap);
        po->datap = NULL;
      }

      if (pp != NULL) {
        if (pp->is_fptr)
          check_func_pp(po, pp, "fptr var call");
        if (pp->is_noreturn)
          po->flags |= OPF_TAIL;
        po->datap = pp;
      }
      continue;
    }

    if (!(po->flags & OPF_JMP) || po->op == OP_RET)
      continue;

    if (po->operand[0].type == OPT_REGMEM) {
      char *p = strchr(po->operand[0].name, '[');
      if (p == NULL)
        goto tailcall;
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
        //ferr(po, "label '%s' not parsed?\n", buf1);
        goto tailcall;
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

    if (po->operand[0].type == OPT_LABEL)
      // assume tail call
      goto tailcall;

    ferr(po, "unhandled branch\n");

tailcall:
    po->op = OP_CALL;
    po->flags |= OPF_TAIL;
    if (i > 0 && ops[i - 1].op == OP_POP)
      po->flags |= OPF_ATAIL;
    i--; // reprocess
  }

  // pass3:
  // - remove dead labels
  // - process calls
  for (i = 0; i < opcnt; i++)
  {
    if (g_labels[i][0] != 0 && g_label_refs[i].i == -1)
      g_labels[i][0] = 0;

    po = &ops[i];
    if (po->flags & OPF_RMD)
      continue;

    if (po->op == OP_CALL)
    {
      tmpname = opr_name(po, 0);
      pp = po->datap;
      if (pp == NULL)
      {
        // indirect call
        pp_c = resolve_icall(i, opcnt, &l);
        if (pp_c != NULL) {
          pp = proto_clone(pp_c);
          my_assert_not(pp, NULL);
          if (l)
            // not resolved just to single func
            pp->is_fptr = 1;
        }
        if (pp == NULL) {
          pp = calloc(1, sizeof(*pp));
          my_assert_not(pp, NULL);
          pp->is_fptr = 1;
          ret = scan_for_esp_adjust(i + 1, opcnt, &j, &l);
          if (ret < 0) {
            if (!g_allow_regfunc)
              ferr(po, "non-__cdecl indirect call unhandled yet\n");
            pp->is_unresolved = 1;
            j = 0;
          }
          j /= 4;
          if (j > ARRAY_SIZE(pp->arg))
            ferr(po, "esp adjust too large: %d\n", j);
          pp->ret_type.name = strdup("int");
          pp->argc = pp->argc_stack = j;
          for (arg = 0; arg < pp->argc; arg++)
            pp->arg[arg].type.name = strdup("int");
        }
        po->datap = pp;
      }

      // look for and make use of esp adjust
      ret = -1;
      if (!pp->is_stdcall && pp->argc_stack > 0)
        ret = scan_for_esp_adjust(i + 1, opcnt, &j, &l);
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
        if (ops[ret].op == OP_POP && j > 4) {
          // deal with multi-pop stack adjust
          j = pp->argc_stack;
          while (ops[ret].op == OP_POP && j > 0 && ret < opcnt) {
            ops[ret].flags |= OPF_RMD;
            j--;
            ret++;
          }
        }
        else if (!l) {
          // a bit of a hack, but deals with use of
          // single adj for multiple calls
          ops[ret].operand[1].val -= j;
        }
      }
      else if (pp->is_vararg)
        ferr(po, "missing esp_adjust for vararg func '%s'\n",
          pp->name);

      if (!pp->is_unresolved && !(po->flags & OPF_ATAIL)) {
        // since we know the args, collect them
        collect_call_args(po, i, pp, &regmask, &save_arg_vars,
          i + opcnt * 2);
      }

      if (strstr(pp->ret_type.name, "int64"))
        need_tmp64 = 1;
    }
  }

  // pass4:
  // - find POPs for PUSHes, rm both
  // - scan for STD/CLD, propagate DF
  // - scan for all used registers
  // - find flag set ops for their users
  // - do unreselved calls
  // - declare indirect functions
  for (i = 0; i < opcnt; i++) {
    po = &ops[i];
    if (po->flags & OPF_RMD)
      continue;

    if (po->op == OP_PUSH && (po->flags & OPF_RSAVE)) {
      reg = po->operand[0].reg;
      if (!(regmask & (1 << reg)))
        // not a reg save after all, rerun scan_for_pop
        po->flags &= ~OPF_RSAVE;
      else
        regmask_save |= 1 << reg;
    }

    if (po->op == OP_PUSH && po->argnum == 0
      && !(po->flags & OPF_RSAVE))
    {
      if (po->operand[0].type == OPT_REG)
      {
        reg = po->operand[0].reg;
        if (reg < 0)
          ferr(po, "reg not set for push?\n");

        depth = 0;
        ret = scan_for_pop(i + 1, opcnt,
                po->operand[0].name, i + opcnt * 3, 0, &depth, 0);
        if (ret == 1) {
          if (depth > 1)
            ferr(po, "too much depth: %d\n", depth);

          po->flags |= OPF_RMD;
          scan_for_pop(i + 1, opcnt, po->operand[0].name,
            i + opcnt * 4, 0, &depth, 1);
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
      else if (po->operand[0].type == OPT_CONST) {
        for (j = i + 1; j < opcnt; j++) {
          if ((ops[j].flags & (OPF_JMP|OPF_TAIL|OPF_RSAVE))
            || ops[j].op == OP_PUSH || g_labels[i][0] != 0)
          {
            break;
          }

          if (!(ops[j].flags & OPF_RMD) && ops[j].op == OP_POP)
          {
            po->flags |= OPF_RMD;
            ops[j].datap = po;
            break;
          }
        }
      }
    }

    if (po->op == OP_STD) {
      po->flags |= OPF_DF | OPF_RMD;
      scan_propagate_df(i + 1, opcnt);
    }

    regmask_now = po->regmask_src | po->regmask_dst;
    if (regmask_now & (1 << xBP)) {
      if (g_bp_frame && !(po->flags & OPF_EBP_S)) {
        if (po->regmask_dst & (1 << xBP))
          // compiler decided to drop bp frame and use ebp as scratch
          scan_fwd_set_flags(i, opcnt, i + opcnt * 5, OPF_EBP_S);
        else
          regmask_now &= ~(1 << xBP);
      }
    }

    regmask |= regmask_now;

    if (po->flags & OPF_CC)
    {
      int setters[16], cnt = 0, branched = 0;

      ret = scan_for_flag_set(i, i + opcnt * 6,
              &branched, setters, &cnt);
      if (ret < 0 || cnt <= 0)
        ferr(po, "unable to trace flag setter(s)\n");
      if (cnt > ARRAY_SIZE(setters))
        ferr(po, "too many flag setters\n");

      pfo = split_cond(po, po->op, &dummy);
      for (j = 0; j < cnt; j++)
      {
        tmp_op = &ops[setters[j]]; // flag setter
        pfomask = 0;

        // to get nicer code, we try to delay test and cmp;
        // if we can't because of operand modification, or if we
        // have arith op, or branch, make it calculate flags explicitly
        if (tmp_op->op == OP_TEST || tmp_op->op == OP_CMP)
        {
          if (branched || scan_for_mod(tmp_op, setters[j] + 1, i, 0) >= 0)
            pfomask = 1 << pfo;
        }
        else if (tmp_op->op == OP_CMPS || tmp_op->op == OP_SCAS) {
          pfomask = 1 << pfo;
        }
        else {
          // see if we'll be able to handle based on op result
          if ((tmp_op->op != OP_AND && tmp_op->op != OP_OR
               && pfo != PFO_Z && pfo != PFO_S && pfo != PFO_P)
              || branched
              || scan_for_mod_opr0(tmp_op, setters[j] + 1, i) >= 0)
            pfomask = 1 << pfo;

          if (tmp_op->op == OP_ADD && pfo == PFO_C)
            need_tmp64 = 1;
        }
        if (pfomask) {
          tmp_op->pfomask |= pfomask;
          cond_vars |= pfomask;
        }
        // note: may overwrite, currently not a problem
        po->datap = tmp_op;
      }

      if (po->op == OP_RCL || po->op == OP_RCR
       || po->op == OP_ADC || po->op == OP_SBB)
        cond_vars |= 1 << PFO_C;
    }
    else if (po->op == OP_CMPS || po->op == OP_SCAS) {
      cond_vars |= 1 << PFO_Z;
    }
    else if (po->op == OP_MUL
      || (po->op == OP_IMUL && po->operand_cnt == 1))
    {
      need_tmp64 = 1;
    }
    else if (po->op == OP_CALL) {
      pp = po->datap;
      if (pp == NULL)
        ferr(po, "NULL pp\n");

      if (pp->is_unresolved) {
        int regmask_stack = 0;
        collect_call_args(po, i, pp, &regmask, &save_arg_vars,
          i + opcnt * 2);

        // this is pretty rough guess:
        // see ecx and edx were pushed (and not their saved versions)
        for (arg = 0; arg < pp->argc; arg++) {
          if (pp->arg[arg].reg != NULL)
            continue;

          tmp_op = pp->arg[arg].datap;
          if (tmp_op == NULL)
            ferr(po, "parsed_op missing for arg%d\n", arg);
          if (tmp_op->argnum == 0 && tmp_op->operand[0].type == OPT_REG)
            regmask_stack |= 1 << tmp_op->operand[0].reg;
        }

        if (!((regmask_stack & (1 << xCX))
          && (regmask_stack & (1 << xDX))))
        {
          if (pp->argc_stack != 0
           || ((regmask | regmask_arg) & ((1 << xCX)|(1 << xDX))))
          {
            pp_insert_reg_arg(pp, "ecx");
            pp->is_fastcall = 1;
            regmask_init |= 1 << xCX;
            regmask |= 1 << xCX;
          }
          if (pp->argc_stack != 0
           || ((regmask | regmask_arg) & (1 << xDX)))
          {
            pp_insert_reg_arg(pp, "edx");
            regmask_init |= 1 << xDX;
            regmask |= 1 << xDX;
          }
        }

        // note: __cdecl doesn't fall into is_unresolved category
        if (pp->argc_stack > 0)
          pp->is_stdcall = 1;
      }

      for (arg = 0; arg < pp->argc; arg++) {
        if (pp->arg[arg].reg != NULL) {
          reg = char_array_i(regs_r32,
                  ARRAY_SIZE(regs_r32), pp->arg[arg].reg);
          if (reg < 0)
            ferr(ops, "arg '%s' is not a reg?\n", pp->arg[arg].reg);
          if (!(regmask & (1 << reg))) {
            regmask_init |= 1 << reg;
            regmask |= 1 << reg;
          }
        }
      }

      // declare indirect funcs
      if (pp->is_fptr && !(pp->name[0] != 0 && pp->is_arg)) {
        if (pp->name[0] != 0) {
          memmove(pp->name + 2, pp->name, strlen(pp->name) + 1);
          memcpy(pp->name, "i_", 2);

          // might be declared already
          found = 0;
          for (j = 0; j < i; j++) {
            if (ops[j].op == OP_CALL && (pp_tmp = ops[j].datap)) {
              if (pp_tmp->is_fptr && IS(pp->name, pp_tmp->name)) {
                found = 1;
                break;
              }
            }
          }
          if (found)
            continue;
        }
        else
          snprintf(pp->name, sizeof(pp->name), "icall%d", i);

        fprintf(fout, "  %s (", pp->ret_type.name);
        output_pp_attrs(fout, pp, 0);
        fprintf(fout, "*%s)(", pp->name);
        for (j = 0; j < pp->argc; j++) {
          if (j > 0)
            fprintf(fout, ", ");
          fprintf(fout, "%s a%d", pp->arg[j].type.name, j + 1);
        }
        fprintf(fout, ");\n");
      }
    }
    else if (po->op == OP_RET && !IS(g_func_pp->ret_type.name, "void"))
      regmask |= 1 << xAX;
    else if (po->op == OP_DIV || po->op == OP_IDIV) {
      // 32bit division is common, look for it
      if (po->op == OP_DIV)
        ret = scan_for_reg_clear(i, xDX);
      else
        ret = scan_for_cdq_edx(i);
      if (ret >= 0)
        po->flags |= OPF_32BIT;
      else
        need_tmp64 = 1;
    }

    if (po->op == OP_RCL || po->op == OP_RCR || po->op == OP_XCHG) {
      need_tmp_var = 1;
    }
  }

  // pass4:
  // - confirm regmask_save, it might have been reduced
  if (regmask_save != 0)
  {
    regmask_save = 0;
    for (i = 0; i < opcnt; i++) {
      po = &ops[i];
      if (po->flags & OPF_RMD)
        continue;

      if (po->op == OP_PUSH && (po->flags & OPF_RSAVE))
        regmask_save |= 1 << po->operand[0].reg;
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

  if (g_func_pp->is_vararg)
    fprintf(fout, "  va_list ap;\n");

  // declare arg-registers
  for (i = 0; i < g_func_pp->argc; i++) {
    if (g_func_pp->arg[i].reg != NULL) {
      reg = char_array_i(regs_r32,
              ARRAY_SIZE(regs_r32), g_func_pp->arg[i].reg);
      if (regmask & (1 << reg)) {
        fprintf(fout, "  u32 %s = (u32)a%d;\n",
          g_func_pp->arg[i].reg, i + 1);
      }
      else
        fprintf(fout, "  // %s = a%d; // unused\n",
          g_func_pp->arg[i].reg, i + 1);
      had_decl = 1;
    }
  }

  regmask_now = regmask & ~regmask_arg;
  regmask_now &= ~(1 << xSP);
  if (regmask_now) {
    for (reg = 0; reg < 8; reg++) {
      if (regmask_now & (1 << reg)) {
        fprintf(fout, "  u32 %s", regs_r32[reg]);
        if (regmask_init & (1 << reg))
          fprintf(fout, " = 0");
        fprintf(fout, ";\n");
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

  if (cond_vars) {
    for (i = 0; i < 8; i++) {
      if (cond_vars & (1 << i)) {
        fprintf(fout, "  u32 cond_%s;\n", parsed_flag_op_names[i]);
        had_decl = 1;
      }
    }
  }

  if (need_tmp_var) {
    fprintf(fout, "  u32 tmp;\n");
    had_decl = 1;
  }

  if (need_tmp64) {
    fprintf(fout, "  u64 tmp64;\n");
    had_decl = 1;
  }

  if (had_decl)
    fprintf(fout, "\n");

  if (g_func_pp->is_vararg) {
    if (g_func_pp->argc_stack == 0)
      ferr(ops, "vararg func without stack args?\n");
    fprintf(fout, "  va_start(ap, a%d);\n", g_func_pp->argc);
  }

  // output ops
  for (i = 0; i < opcnt; i++)
  {
    if (g_labels[i][0] != 0) {
      fprintf(fout, "\n%s:\n", g_labels[i]);
      label_pending = 1;

      delayed_flag_op = NULL;
      last_arith_dst = NULL;
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
      tmp_op = po->datap;

      // we go through all this trouble to avoid using parsed_flag_op,
      // which makes generated code much nicer
      if (delayed_flag_op != NULL)
      {
        out_cmp_test(buf1, sizeof(buf1), delayed_flag_op, pfo, is_inv);
        is_delayed = 1;
      }
      else if (last_arith_dst != NULL
        && (pfo == PFO_Z || pfo == PFO_S || pfo == PFO_P
           || (tmp_op && (tmp_op->op == OP_AND || tmp_op->op == OP_OR))
           ))
      {
        out_src_opr_u32(buf3, sizeof(buf3), po, last_arith_dst);
        out_test_for_cc(buf1, sizeof(buf1), po, pfo, is_inv,
          last_arith_dst->lmod, buf3);
        is_delayed = 1;
      }
      else if (tmp_op != NULL) {
        // use preprocessed flag calc results
        if (!(tmp_op->pfomask & (1 << pfo)))
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
      else if (po->op == OP_RCL || po->op == OP_RCR
               || po->op == OP_ADC || po->op == OP_SBB)
      {
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

    if (po->flags & (OPF_REPZ|OPF_REPNZ)) {
      // we need initial flags for ecx=0 case..
      if (i > 0 && ops[i - 1].op == OP_XOR
        && IS(ops[i - 1].operand[0].name,
              ops[i - 1].operand[1].name))
      {
        fprintf(fout, "  cond_z = ");
        if (pfomask & (1 << PFO_C))
          fprintf(fout, "cond_c = ");
        fprintf(fout, "0;\n");
      }
      else if (last_arith_dst != NULL) {
        out_src_opr_u32(buf3, sizeof(buf3), po, last_arith_dst);
        out_test_for_cc(buf1, sizeof(buf1), po, PFO_Z, 0,
          last_arith_dst->lmod, buf3);
        fprintf(fout, "  cond_z = %s;\n", buf1);
      }
      else
        ferr(po, "missing initial ZF\n");
    }

    switch (po->op)
    {
      case OP_MOV:
        assert_operand_cnt(2);
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        fprintf(fout, "  %s = %s;", buf1,
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
        fprintf(fout, "  %s = %s;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
            out_src_opr(buf2, sizeof(buf2), po, &po->operand[1],
              buf3, 0));
        break;

      case OP_XCHG:
        assert_operand_cnt(2);
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        fprintf(fout, "  tmp = %s;",
          out_src_opr(buf1, sizeof(buf1), po, &po->operand[0], "", 0));
        fprintf(fout, " %s = %s;",
          out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
          out_src_opr(buf2, sizeof(buf2), po, &po->operand[1], "", 0));
        fprintf(fout, " %s = tmp;",
          out_dst_opr(buf1, sizeof(buf1), po, &po->operand[1]));
        snprintf(g_comment, sizeof(g_comment), "xchg");
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
        assert_operand_cnt(3);
        if (po->flags & OPF_REP) {
          fprintf(fout, "  for (; ecx != 0; ecx--, edi %c= %d)\n",
            (po->flags & OPF_DF) ? '-' : '+',
            lmod_bytes(po, po->operand[0].lmod));
          fprintf(fout, "    %sedi = eax;",
            lmod_cast_u_ptr(po, po->operand[0].lmod));
          strcpy(g_comment, "rep stos");
        }
        else {
          fprintf(fout, "    %sedi = eax; edi %c= %d;",
            lmod_cast_u_ptr(po, po->operand[0].lmod),
            (po->flags & OPF_DF) ? '-' : '+',
            lmod_bytes(po, po->operand[0].lmod));
          strcpy(g_comment, "stos");
        }
        break;

      case OP_MOVS:
        assert_operand_cnt(3);
        j = lmod_bytes(po, po->operand[0].lmod);
        strcpy(buf1, lmod_cast_u_ptr(po, po->operand[0].lmod));
        l = (po->flags & OPF_DF) ? '-' : '+';
        if (po->flags & OPF_REP) {
          fprintf(fout,
            "  for (; ecx != 0; ecx--, edi %c= %d, esi %c= %d)\n",
            l, j, l, j);
          fprintf(fout,
            "    %sedi = %sesi;", buf1, buf1);
          strcpy(g_comment, "rep movs");
        }
        else {
          fprintf(fout, "    %sedi = %sesi; edi %c= %d; esi %c= %d;",
            buf1, buf1, l, j, l, j);
          strcpy(g_comment, "movs");
        }
        break;

      case OP_CMPS:
        // repe ~ repeat while ZF=1
        assert_operand_cnt(3);
        j = lmod_bytes(po, po->operand[0].lmod);
        strcpy(buf1, lmod_cast_u_ptr(po, po->operand[0].lmod));
        l = (po->flags & OPF_DF) ? '-' : '+';
        if (po->flags & OPF_REP) {
          fprintf(fout,
            "  for (; ecx != 0; ecx--, edi %c= %d, esi %c= %d) {\n",
            l, j, l, j);
          if (pfomask & (1 << PFO_C)) {
            // ugh..
            fprintf(fout,
            "    cond_c = %sedi < %sesi;\n", buf1, buf1);
            pfomask &= ~(1 << PFO_C);
          }
          fprintf(fout,
            "    if ((cond_z = (%sedi == %sesi)) %s 0)\n",
              buf1, buf1, (po->flags & OPF_REPZ) ? "==" : "!=");
          fprintf(fout,
            "      break;\n"
            "  }");
          snprintf(g_comment, sizeof(g_comment), "rep%s cmps",
            (po->flags & OPF_REPZ) ? "e" : "ne");
        }
        else {
          fprintf(fout,
            "    cond_z = (%sedi = %sesi); edi %c= %d; esi %c= %d;",
            buf1, buf1, l, j, l, j);
          strcpy(g_comment, "cmps");
        }
        pfomask &= ~(1 << PFO_Z);
        last_arith_dst = NULL;
        delayed_flag_op = NULL;
        break;

      case OP_SCAS:
        // only does ZF (for now)
        // repe ~ repeat while ZF=1
        assert_operand_cnt(3);
        j = lmod_bytes(po, po->operand[0].lmod);
        l = (po->flags & OPF_DF) ? '-' : '+';
        if (po->flags & OPF_REP) {
          fprintf(fout,
            "  for (; ecx != 0; ecx--, edi %c= %d)\n", l, j);
          fprintf(fout,
            "    if ((cond_z = (%seax == %sedi)) %s 0)\n",
              lmod_cast_u(po, po->operand[0].lmod),
              lmod_cast_u_ptr(po, po->operand[0].lmod),
              (po->flags & OPF_REPZ) ? "==" : "!=");
          fprintf(fout,
            "      break;");
          snprintf(g_comment, sizeof(g_comment), "rep%s scas",
            (po->flags & OPF_REPZ) ? "e" : "ne");
        }
        else {
          fprintf(fout, "    cond_z = (%seax = %sedi); edi %c= %d;",
              lmod_cast_u(po, po->operand[0].lmod),
              lmod_cast_u_ptr(po, po->operand[0].lmod), l, j);
          strcpy(g_comment, "scas");
        }
        pfomask &= ~(1 << PFO_Z);
        last_arith_dst = NULL;
        delayed_flag_op = NULL;
        break;

      // arithmetic w/flags
      case OP_AND:
      case OP_OR:
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        // fallthrough
      dualop_arith:
        assert_operand_cnt(2);
        fprintf(fout, "  %s %s= %s;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
            op_to_c(po),
            out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]));
        output_std_flags(fout, po, &pfomask, buf1);
        last_arith_dst = &po->operand[0];
        delayed_flag_op = NULL;
        break;

      case OP_SHL:
      case OP_SHR:
        assert_operand_cnt(2);
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        if (pfomask & (1 << PFO_C)) {
          if (po->operand[1].type == OPT_CONST) {
            l = lmod_bytes(po, po->operand[0].lmod) * 8;
            j = po->operand[1].val;
            j %= l;
            if (j != 0) {
              if (po->op == OP_SHL)
                j = l - j;
              else
                j -= 1;
              fprintf(fout, "  cond_c = (%s >> %d) & 1;\n",
                buf1, j);
            }
            else
              ferr(po, "zero shift?\n");
          }
          else
            ferr(po, "TODO\n");
          pfomask &= ~(1 << PFO_C);
        }
        fprintf(fout, "  %s %s= %s;", buf1, op_to_c(po),
            out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]));
        output_std_flags(fout, po, &pfomask, buf1);
        last_arith_dst = &po->operand[0];
        delayed_flag_op = NULL;
        break;

      case OP_SAR:
        assert_operand_cnt(2);
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        fprintf(fout, "  %s = %s%s >> %s;", buf1,
          lmod_cast_s(po, po->operand[0].lmod), buf1,
          out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]));
        output_std_flags(fout, po, &pfomask, buf1);
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
        output_std_flags(fout, po, &pfomask, buf1);
        last_arith_dst = &po->operand[0];
        delayed_flag_op = NULL;
        break;

      case OP_RCL:
      case OP_RCR:
        assert_operand_cnt(2);
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        l = lmod_bytes(po, po->operand[0].lmod) * 8;
        if (po->operand[1].type == OPT_CONST) {
          j = po->operand[1].val % l;
          if (j == 0)
            ferr(po, "zero rotate\n");
          fprintf(fout, "  tmp = (%s >> %d) & 1;\n",
            buf1, (po->op == OP_RCL) ? (l - j) : (j - 1));
          if (po->op == OP_RCL) {
            fprintf(fout,
              "  %s = (%s << %d) | (cond_c << %d)",
              buf1, buf1, j, j - 1);
            if (j != 1)
              fprintf(fout, " | (%s >> %d)", buf1, l + 1 - j);
          }
          else {
            fprintf(fout,
              "  %s = (%s >> %d) | (cond_c << %d)",
              buf1, buf1, j, l - j);
            if (j != 1)
              fprintf(fout, " | (%s << %d)", buf1, l + 1 - j);
          }
          fprintf(fout, ";\n");
          fprintf(fout, "  cond_c = tmp;");
        }
        else
          ferr(po, "TODO\n");
        strcpy(g_comment, (po->op == OP_RCL) ? "rcl" : "rcr");
        output_std_flags(fout, po, &pfomask, buf1);
        last_arith_dst = &po->operand[0];
        delayed_flag_op = NULL;
        break;

      case OP_XOR:
        assert_operand_cnt(2);
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        if (IS(opr_name(po, 0), opr_name(po, 1))) {
          // special case for XOR
          if (pfomask & (1 << PFO_BE)) { // weird, but it happens..
            fprintf(fout, "  cond_be = 1;\n");
            pfomask &= ~(1 << PFO_BE);
          }
          fprintf(fout, "  %s = 0;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]));
          last_arith_dst = &po->operand[0];
          delayed_flag_op = NULL;
          break;
        }
        goto dualop_arith;

      case OP_ADD:
        assert_operand_cnt(2);
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        if (pfomask & (1 << PFO_C)) {
          fprintf(fout, "  tmp64 = (u64)%s + %s;\n",
            out_src_opr_u32(buf1, sizeof(buf1), po, &po->operand[0]),
            out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]));
          fprintf(fout, "  cond_c = tmp64 >> 32;\n");
          fprintf(fout, "  %s = (u32)tmp64;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]));
          strcat(g_comment, "add64");
          pfomask &= ~(1 << PFO_C);
          output_std_flags(fout, po, &pfomask, buf1);
          last_arith_dst = &po->operand[0];
          delayed_flag_op = NULL;
          break;
        }
        goto dualop_arith;

      case OP_SUB:
        assert_operand_cnt(2);
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        if (pfomask & (1 << PFO_C)) {
          fprintf(fout, "  cond_c = %s < %s;\n",
            out_src_opr_u32(buf1, sizeof(buf1), po, &po->operand[0]),
            out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]));
          pfomask &= ~(1 << PFO_C);
        }
        goto dualop_arith;

      case OP_ADC:
      case OP_SBB:
        assert_operand_cnt(2);
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        if (po->op == OP_SBB
          && IS(po->operand[0].name, po->operand[1].name))
        {
          // avoid use of unitialized var
          fprintf(fout, "  %s = -cond_c;", buf1);
          // carry remains what it was
          pfomask &= ~(1 << PFO_C);
        }
        else {
          fprintf(fout, "  %s %s= %s + cond_c;", buf1, op_to_c(po),
            out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]));
        }
        output_std_flags(fout, po, &pfomask, buf1);
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
        output_std_flags(fout, po, &pfomask, buf1);
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
        if (po->operand_cnt == 2) {
          propagate_lmod(po, &po->operand[0], &po->operand[1]);
          goto dualop_arith;
        }
        if (po->operand_cnt == 3)
          ferr(po, "TODO imul3\n");
        // fallthrough
      case OP_MUL:
        assert_operand_cnt(1);
        strcpy(buf1, po->op == OP_IMUL ? "(s64)(s32)" : "(u64)");
        fprintf(fout, "  tmp64 = %seax * %s%s;\n", buf1, buf1,
          out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[0]));
        fprintf(fout, "  edx = tmp64 >> 32;\n");
        fprintf(fout, "  eax = tmp64;");
        last_arith_dst = NULL;
        delayed_flag_op = NULL;
        break;

      case OP_DIV:
      case OP_IDIV:
        assert_operand_cnt(1);
        if (po->operand[0].lmod != OPLM_DWORD)
          ferr(po, "unhandled lmod %d\n", po->operand[0].lmod);

        out_src_opr_u32(buf1, sizeof(buf1), po, &po->operand[0]);
        strcpy(buf2, lmod_cast(po, po->operand[0].lmod,
          po->op == OP_IDIV));
        switch (po->operand[0].lmod) {
        case OPLM_DWORD:
          if (po->flags & OPF_32BIT)
            snprintf(buf3, sizeof(buf3), "%seax", buf2);
          else {
            fprintf(fout, "  tmp64 = ((u64)edx << 32) | eax;\n");
            snprintf(buf3, sizeof(buf3), "%stmp64",
              (po->op == OP_IDIV) ? "(s64)" : "");
          }
          if (po->operand[0].type == OPT_REG
            && po->operand[0].reg == xDX)
          {
            fprintf(fout, "  eax = %s / %s%s;", buf3, buf2, buf1);
            fprintf(fout, "  edx = %s %% %s%s;\n", buf3, buf2, buf1);
          }
          else {
            fprintf(fout, "  edx = %s %% %s%s;\n", buf3, buf2, buf1);
            fprintf(fout, "  eax = %s / %s%s;", buf3, buf2, buf1);
          }
          break;
        default:
          ferr(po, "unhandled division type\n");
        }
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

      case OP_JECXZ:
        fprintf(fout, "  if (ecx == 0)\n");
        fprintf(fout, "    goto %s;", po->operand[0].name);
        strcat(g_comment, "jecxz");
        break;

      case OP_JMP:
        assert_operand_cnt(1);
        last_arith_dst = NULL;
        delayed_flag_op = NULL;

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
        my_assert_not(pp, NULL);

        if (pp->is_fptr && !pp->is_arg)
          fprintf(fout, "  %s = %s;\n", pp->name,
            out_src_opr(buf1, sizeof(buf1), po, &po->operand[0],
              "(void *)", 0));

        fprintf(fout, "  ");
        if (strstr(pp->ret_type.name, "int64")) {
          if (po->flags & OPF_TAIL)
            ferr(po, "int64 and tail?\n");
          fprintf(fout, "tmp64 = ");
        }
        else if (!IS(pp->ret_type.name, "void")) {
          if (po->flags & OPF_TAIL) {
            if (!IS(g_func_pp->ret_type.name, "void")) {
              fprintf(fout, "return ");
              if (g_func_pp->ret_type.is_ptr != pp->ret_type.is_ptr)
                fprintf(fout, "(%s)", g_func_pp->ret_type.name);
            }
          }
          else if (regmask & (1 << xAX)) {
            fprintf(fout, "eax = ");
            if (pp->ret_type.is_ptr)
              fprintf(fout, "(u32)");
          }
        }

        if (pp->name[0] == 0)
          ferr(po, "missing pp->name\n");
        fprintf(fout, "%s%s(", pp->name,
          pp->has_structarg ? "_sa" : "");

        if (po->flags & OPF_ATAIL) {
          if (pp->argc_stack != g_func_pp->argc_stack
            || (pp->argc_stack > 0
                && pp->is_stdcall != g_func_pp->is_stdcall))
            ferr(po, "incompatible tailcall\n");

          for (arg = j = 0; arg < pp->argc; arg++) {
            if (arg > 0)
              fprintf(fout, ", ");

            cast[0] = 0;
            if (pp->arg[arg].type.is_ptr)
              snprintf(cast, sizeof(cast), "(%s)",
                pp->arg[arg].type.name);

            if (pp->arg[arg].reg != NULL) {
              fprintf(fout, "%s%s", cast, pp->arg[arg].reg);
              continue;
            }
            // stack arg
            for (; j < g_func_pp->argc; j++)
              if (g_func_pp->arg[j].reg == NULL)
                break;
            fprintf(fout, "%sa%d", cast, j + 1);
            j++;
          }
        }
        else {
          for (arg = 0; arg < pp->argc; arg++) {
            if (arg > 0)
              fprintf(fout, ", ");

            cast[0] = 0;
            if (pp->arg[arg].type.is_ptr)
              snprintf(cast, sizeof(cast), "(%s)",
                pp->arg[arg].type.name);

            if (pp->arg[arg].reg != NULL) {
              fprintf(fout, "%s%s", cast, pp->arg[arg].reg);
              continue;
            }

            // stack arg
            tmp_op = pp->arg[arg].datap;
            if (tmp_op == NULL)
              ferr(po, "parsed_op missing for arg%d\n", arg);
            if (tmp_op->argnum != 0) {
              fprintf(fout, "%ss_a%d", cast, tmp_op->argnum);
            }
            else {
              fprintf(fout, "%s",
                out_src_opr(buf1, sizeof(buf1),
                  tmp_op, &tmp_op->operand[0], cast, 0));
            }
          }
        }
        fprintf(fout, ");");

        if (strstr(pp->ret_type.name, "int64")) {
          fprintf(fout, "\n");
          fprintf(fout, "  edx = tmp64 >> 32;\n");
          fprintf(fout, "  eax = tmp64;");
        }

        if (pp->is_unresolved) {
          snprintf(buf3, sizeof(buf3), " unresoved %dreg",
            pp->argc_reg);
          strcat(g_comment, buf3);
        }

        if (po->flags & OPF_TAIL) {
          ret = 0;
          if (i == opcnt - 1 || pp->is_noreturn)
            ret = 0;
          else if (IS(pp->ret_type.name, "void"))
            ret = 1;
          else if (IS(g_func_pp->ret_type.name, "void"))
            ret = 1;
          // else already handled as 'return f()'

          if (ret) {
            if (!IS(g_func_pp->ret_type.name, "void")) {
              ferr(po, "int func -> void func tailcall?\n");
            }
            else {
              fprintf(fout, "\n  return;");
              strcat(g_comment, " ^ tailcall");
            }
          }
          else
            strcat(g_comment, " tailcall");
        }
        if (pp->is_noreturn)
          strcat(g_comment, " noreturn");
        if ((po->flags & OPF_ATAIL) && pp->argc_stack > 0)
          strcat(g_comment, " argframe");
        delayed_flag_op = NULL;
        last_arith_dst = NULL;
        break;

      case OP_RET:
        if (g_func_pp->is_vararg)
          fprintf(fout, "  va_end(ap);\n");
 
        if (IS(g_func_pp->ret_type.name, "void")) {
          if (i != opcnt - 1 || label_pending)
            fprintf(fout, "  return;");
        }
        else if (g_func_pp->ret_type.is_ptr) {
          fprintf(fout, "  return (%s)eax;",
            g_func_pp->ret_type.name);
        }
        else if (IS(g_func_pp->ret_type.name, "__int64"))
          fprintf(fout, "  return ((u64)edx << 32) | eax;");
        else
          fprintf(fout, "  return eax;");

        last_arith_dst = NULL;
        delayed_flag_op = NULL;
        break;

      case OP_PUSH:
        if (po->argnum != 0) {
          // special case - saved func arg
          out_src_opr_u32(buf1, sizeof(buf1), po, &po->operand[0]);
          fprintf(fout, "  s_a%d = %s;", po->argnum, buf1);
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
        else if (po->datap != NULL) {
          // push/pop pair
          tmp_op = po->datap;
          out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
          fprintf(fout, "  %s = %s;", buf1,
            out_src_opr(buf2, sizeof(buf2),
              tmp_op, &tmp_op->operand[0],
              po->operand[0].is_ptr ? "(void *)" : "", 0));
          break;
        }
        ferr(po, "stray pop encountered\n");
        break;

      case OP_NOP:
        no_output = 1;
        break;

      default:
        no_output = 1;
        ferr(po, "unhandled op type %d, flags %x\n",
          po->op, po->flags);
        break;
    }

    if (g_comment[0] != 0) {
      char *p = g_comment;
      while (my_isblank(*p))
        p++;
      fprintf(fout, "  // %s", p);
      g_comment[0] = 0;
      no_output = 0;
    }
    if (!no_output)
      fprintf(fout, "\n");

    // some sanity checking
    if (po->flags & OPF_REP) {
      if (po->op != OP_STOS && po->op != OP_MOVS
          && po->op != OP_CMPS && po->op != OP_SCAS)
        ferr(po, "unexpected rep\n");
      if (!(po->flags & (OPF_REPZ|OPF_REPNZ))
          && (po->op == OP_CMPS || po->op == OP_SCAS))
        ferr(po, "cmps/scas with plain rep\n");
    }
    if ((po->flags & (OPF_REPZ|OPF_REPNZ))
        && po->op != OP_CMPS && po->op != OP_SCAS)
      ferr(po, "unexpected repz/repnz\n");

    if (pfomask != 0)
      ferr(po, "missed flag calc, pfomask=%x\n", pfomask);

    // see is delayed flag stuff is still valid
    if (delayed_flag_op != NULL && delayed_flag_op != po) {
      if (is_any_opr_modified(delayed_flag_op, po, 0))
        delayed_flag_op = NULL;
    }

    if (last_arith_dst != NULL && last_arith_dst != &po->operand[0]) {
      if (is_opr_modified(last_arith_dst, po))
        last_arith_dst = NULL;
    }

    label_pending = 0;
  }

  if (g_stack_fsz && !g_stack_frame_used)
    fprintf(fout, "  (void)sf;\n");

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
      if (pp)
        proto_release(pp);
    }
  }
  g_func_pp = NULL;
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
  int asmln;
};

static struct chunk_item *func_chunks;
static int func_chunk_cnt;
static int func_chunk_alloc;

static void add_func_chunk(FILE *fasm, const char *name, int line)
{
  if (func_chunk_cnt >= func_chunk_alloc) {
    func_chunk_alloc *= 2;
    func_chunks = realloc(func_chunks,
      func_chunk_alloc * sizeof(func_chunks[0]));
    my_assert_not(func_chunks, NULL);
  }
  func_chunks[func_chunk_cnt].fptr = ftell(fasm);
  func_chunks[func_chunk_cnt].name = strdup(name);
  func_chunks[func_chunk_cnt].asmln = line;
  func_chunk_cnt++;
}

static int cmp_chunks(const void *p1, const void *p2)
{
  const struct chunk_item *c1 = p1, *c2 = p2;
  return strcmp(c1->name, c2->name);
}

static int cmpstringp(const void *p1, const void *p2)
{
  return strcmp(*(char * const *)p1, *(char * const *)p2);
}

static void scan_ahead(FILE *fasm)
{
  char words[2][256];
  char line[256];
  long oldpos;
  int oldasmln;
  int wordc;
  char *p;
  int i;

  oldpos = ftell(fasm);
  oldasmln = asmln;

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
      for (i = 0; line[i] != 0; i++)
        if (line[i] == '\t')
          line[i] = ' ';

      if (p[2] == 'S' && IS_START(p, "; START OF FUNCTION CHUNK FOR "))
      {
        p += 30;
        next_word(words[0], sizeof(words[0]), p);
        if (words[0][0] == 0)
          aerr("missing name for func chunk?\n");

        add_func_chunk(fasm, words[0], asmln);
      }
      continue;
    } // *p == ';'

    for (wordc = 0; wordc < ARRAY_SIZE(words); wordc++) {
      words[wordc][0] = 0;
      p = sskip(next_word_s(words[wordc], sizeof(words[0]), p));
      if (*p == 0 || *p == ';') {
        wordc++;
        break;
      }
    }

    if (wordc == 2 && IS(words[1], "ends"))
      break;
  }

  fseek(fasm, oldpos, SEEK_SET);
  asmln = oldasmln;
}

int main(int argc, char *argv[])
{
  FILE *fout, *fasm, *frlist;
  struct parsed_data *pd = NULL;
  int pd_alloc = 0;
  char **rlist = NULL;
  int rlist_len = 0;
  int rlist_alloc = 0;
  int func_chunks_used = 0;
  int func_chunks_sorted = 0;
  int func_chunk_i = -1;
  long func_chunk_ret = 0;
  int func_chunk_ret_ln = 0;
  int scanned_ahead = 0;
  char line[256];
  char words[20][256];
  enum opr_lenmod lmod;
  char *sctproto = NULL;
  int in_func = 0;
  int pending_endp = 0;
  int skip_func = 0;
  int skip_warned = 0;
  int eq_alloc;
  int verbose = 0;
  int arg_out;
  int arg;
  int pi = 0;
  int i, j;
  int ret, len;
  char *p;
  int wordc;

  for (arg = 1; arg < argc; arg++) {
    if (IS(argv[arg], "-v"))
      verbose = 1;
    else if (IS(argv[arg], "-rf"))
      g_allow_regfunc = 1;
    else
      break;
  }

  if (argc < arg + 3) {
    printf("usage:\n%s [-v] [-rf] <.c> <.asm> <hdrf> [rlist]*\n",
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

  memset(words, 0, sizeof(words));

  for (; arg < argc; arg++) {
    frlist = fopen(argv[arg], "r");
    my_assert_not(frlist, NULL);

    while (fgets(line, sizeof(line), frlist)) {
      p = sskip(line);
      if (*p == 0 || *p == ';')
        continue;
      if (*p == '#') {
        if (IS_START(p, "#if 0")
         || (g_allow_regfunc && IS_START(p, "#if NO_REGFUNC")))
        {
          skip_func = 1;
        }
        else if (IS_START(p, "#endif"))
          skip_func = 0;
        continue;
      }
      if (skip_func)
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
    skip_func = 0;

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

    // get rid of random tabs
    for (i = 0; line[i] != 0; i++)
      if (line[i] == '\t')
        line[i] = ' ';

    if (*p == ';')
    {
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
          aerr("missing name for func chunk?\n");

        if (!scanned_ahead) {
          add_func_chunk(fasm, words[0], asmln);
          func_chunks_sorted = 0;
        }
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
            asmln = func_chunks[func_chunk_i].asmln;
            func_chunk_i++;
          }
          else {
            if (func_chunk_ret == 0)
              aerr("no return from chunk?\n");
            fseek(fasm, func_chunk_ret, SEEK_SET);
            asmln = func_chunk_ret_ln;
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
          if (addr > f_addr && !scanned_ahead) {
            anote("scan_ahead caused by '%s', addr %lx\n",
              g_func, addr);
            scan_ahead(fasm);
            scanned_ahead = 1;
            func_chunks_sorted = 0;
          }
        }
      }
      continue;
    } // *p == ';'

parse_words:
    for (i = wordc; i < ARRAY_SIZE(words); i++)
      words[i][0] = 0;
    for (wordc = 0; wordc < ARRAY_SIZE(words); wordc++) {
      p = sskip(next_word_s(words[wordc], sizeof(words[0]), p));
      if (*p == 0 || *p == ';') {
        wordc++;
        break;
      }
    }
    if (*p != 0 && *p != ';')
      aerr("too many words\n");

    // alow asm patches in comments
    if (*p == ';') {
      if (IS_START(p, "; sctpatch:")) {
        p = sskip(p + 11);
        if (*p == 0 || *p == ';')
          continue;
        goto parse_words; // lame
      }
      if (IS_START(p, "; sctproto:")) {
        sctproto = strdup(p + 11);
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
          if (pd == NULL) {
            if (verbose)
              anote("skipping alignment byte?\n");
            continue;
          }
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
      if (bsearch(&p, rlist, rlist_len, sizeof(rlist[0]), cmpstringp))
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

      if ((g_ida_func_attr & IDAFA_THUNK) && pi == 1
        && ops[0].op == OP_JMP && ops[0].operand[0].had_ds)
      {
        // import jump
        skip_func = 1;
      }

      if (!skip_func && func_chunks_used) {
        // start processing chunks
        struct chunk_item *ci, key = { g_func, 0 };

        func_chunk_ret = ftell(fasm);
        func_chunk_ret_ln = asmln;
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
        asmln = func_chunks[func_chunk_i].asmln;
        func_chunk_i++;
        continue;
      }
      pending_endp = 1;
      continue;
    }

    if (wordc == 2 && IS(words[1], "ends"))
      break;

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

    if (wordc > 1 && IS(words[1], "="))
    {
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

    if (sctproto != NULL) {
      if (ops[pi].op == OP_CALL)
        ops[pi].datap = sctproto;
      sctproto = NULL;
    }
    pi++;
  }

  fclose(fout);
  fclose(fasm);
  fclose(g_fhdr);

  return 0;
}

// vim:ts=2:shiftwidth=2:expandtab
