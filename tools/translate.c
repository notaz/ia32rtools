/*
 * ia32rtools
 * (C) notaz, 2013-2015
 *
 * This work is licensed under the terms of 3-clause BSD license.
 * See COPYING file in the top-level directory.
 *
 * recognized asm hint comments:
 * sctattr - function attributes (see code)
 * sctend  - force end of function/chunk
 * sctpatch: <p> - replace current asm line with <p>
 * sctproto: <p> - prototype of ref'd function or struct
 * sctref  - variable is referenced, make global
 * sctskip_start - start of skipped code chunk (inclusive)
 * sctskip_end   - end of skipped code chunk (inclusive)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <math.h>
#include <errno.h>

#include "my_assert.h"
#include "my_str.h"
#include "common.h"

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
  OPF_RMD    = (1 << 0), /* removed from code generation */
  OPF_DATA   = (1 << 1), /* data processing - writes to dst opr */
  OPF_FLAGS  = (1 << 2), /* sets flags */
  OPF_JMP    = (1 << 3), /* branch, call */
  OPF_CJMP   = (1 << 4), /* cond. branch (cc or jecxz/loop) */
  OPF_CC     = (1 << 5), /* uses flags */
  OPF_TAIL   = (1 << 6), /* ret or tail call */
  OPF_RSAVE  = (1 << 7), /* push/pop is local reg save/load */
  OPF_REP    = (1 << 8), /* prefixed by rep */
  OPF_REPZ   = (1 << 9), /* rep is repe/repz */
  OPF_REPNZ  = (1 << 10), /* rep is repne/repnz */
  OPF_FARG   = (1 << 11), /* push collected as func arg */
  OPF_FARGNR = (1 << 12), /* push collected as func arg (no reuse) */
  OPF_EBP_S  = (1 << 13), /* ebp used as scratch here, not BP */
  OPF_DF     = (1 << 14), /* DF flag set */
  OPF_ATAIL  = (1 << 15), /* tail call with reused arg frame */
  OPF_32BIT  = (1 << 16), /* enough to do 32bit for this op */
  OPF_LOCK   = (1 << 17), /* op has lock prefix */
  OPF_VAPUSH = (1 << 18), /* vararg ptr push (as call arg) */
  OPF_DONE   = (1 << 19), /* already fully handled by analysis */
  OPF_PPUSH  = (1 << 20), /* part of complex push-pop graph */
  OPF_NOREGS = (1 << 21), /* don't track regs of this op */
  OPF_FPUSH  = (1 << 22), /* pushes x87 stack */
  OPF_FPOP   = (1 << 23), /* pops x87 stack */
  OPF_FPOPP  = (1 << 24), /* pops x87 stack twice */
  OPF_FSHIFT = (1 << 25), /* x87 stack shift is actually needed */
  OPF_FINT   = (1 << 26), /* integer float op arg */
};

enum op_op {
	OP_INVAL,
	OP_NOP,
	OP_PUSH,
	OP_POP,
	OP_PUSHA,
	OP_POPA,
	OP_LEAVE,
	OP_MOV,
	OP_LEA,
	OP_MOVZX,
	OP_MOVSX,
	OP_XCHG,
	OP_NOT,
	OP_XLAT,
	OP_CDQ,
	OP_BSWAP,
	OP_LODS,
	OP_STOS,
	OP_MOVS,
	OP_CMPS,
	OP_SCAS,
	OP_RDTSC,
	OP_CPUID,
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
	OP_SHLD,
	OP_SHRD,
	OP_ROL,
	OP_ROR,
	OP_RCL,
	OP_RCR,
	OP_ADC,
	OP_SBB,
	OP_BSF,
	OP_BSR,
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
	OP_LOOP,
	OP_JCC,
	OP_SCC,
  // x87
  OP_FLD,
  OP_FILD,
  OP_FLDc,
  OP_FST,
  OP_FIST,
  OP_FABS,
  OP_FADD,
  OP_FDIV,
  OP_FMUL,
  OP_FSUB,
  OP_FDIVR,
  OP_FSUBR,
  OP_FIADD,
  OP_FIDIV,
  OP_FIMUL,
  OP_FISUB,
  OP_FIDIVR,
  OP_FISUBR,
  OP_FCOM,
  OP_FNSTSW,
  OP_FCHS,
  OP_FCOS,
  OP_FPATAN,
  OP_FPTAN,
  OP_FSIN,
  OP_FSQRT,
  OP_FXCH,
  OP_FYL2X,
  // mmx
  OP_EMMS,
  // pseudo-ops for lib calls
  OPP_ALLSHL,
  OPP_ALLSHR,
  OPP_FTOL,
  OPP_CIPOW,
  OPP_ABORT,
  // undefined
  OP_UD2,
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
	OPLM_QWORD,
};

#define MAX_EXITS 128

#define MAX_OPERANDS 3
#define NAMELEN 112

#define OPR_INIT(type_, lmod_, reg_) \
  { type_, lmod_, reg_, }

struct parsed_opr {
  enum opr_type type;
  enum opr_lenmod lmod;
  int reg;
  unsigned int is_ptr:1;   // pointer in C
  unsigned int is_array:1; // array in C
  unsigned int type_from_var:1; // .. in header, sometimes wrong
  unsigned int size_mismatch:1; // type override differs from C
  unsigned int size_lt:1;  // type override is larger than C
  unsigned int segment:7;  // had segment override (enum segment)
  const struct parsed_proto *pp; // for OPT_LABEL
  unsigned int val;
  char name[NAMELEN];
};

struct parsed_op {
  enum op_op op;
  struct parsed_opr operand[MAX_OPERANDS];
  unsigned int flags;
  unsigned char pfo;
  unsigned char pfo_inv;
  unsigned char operand_cnt;
  unsigned char p_argnum; // arg push: call's saved arg #
  unsigned char p_arggrp; // arg push: arg group # for above
  unsigned char p_argpass;// arg push: arg of host func
  short pad;
  int regmask_src;        // all referensed regs
  int regmask_dst;
  int pfomask;            // flagop: parsed_flag_op that can't be delayed
  int cc_scratch;         // scratch storage during analysis
  int bt_i;               // branch target for branches
  struct parsed_data *btj;// branch targets for jumptables
  struct parsed_proto *pp;// parsed_proto for OP_CALL
  void *datap;
  int asmln;
};

// datap:
// on start:  function/data type hint (sctproto)
// after analysis:
// (OPF_CC) - points to one of (OPF_FLAGS) that affects cc op
// OP_PUSH  - points to OP_POP in complex push/pop graph
// OP_POP   - points to OP_PUSH in simple push/pop pair
// OP_FCOM  - needed_status_word_bits | (is_z_check << 16)

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

// sctattr
enum sct_func_attr {
  SCTFA_CLEAR_SF   = (1 << 0), // clear stack frame
  SCTFA_CLEAR_REGS = (1 << 1), // clear registers (mask)
  SCTFA_RM_REGS    = (1 << 2), // don't emit regs (mask)
  SCTFA_NOWARN     = (1 << 3), // don't try to detect problems
  SCTFA_ARGFRAME   = (1 << 4), // copy all args to a struct, in order
  SCTFA_UA_FLOAT   = (1 << 5), // emit float i/o helpers for alignemnt
};

enum x87_const {
  X87_CONST_1 = 1,
  X87_CONST_L2T,
  X87_CONST_L2E,
  X87_CONST_PI,
  X87_CONST_LG2,
  X87_CONST_LN2,
  X87_CONST_Z,
};

enum segment {
  SEG_CS = 1,
  SEG_DS,
  SEG_SS,
  SEG_ES,
  SEG_FS,
  SEG_GS,
};

#define MAX_OPS     4096
#define MAX_ARG_GRP 2

static struct parsed_op ops[MAX_OPS];
static struct parsed_equ *g_eqs;
static int g_eqcnt;
static char *g_labels[MAX_OPS];
static struct label_ref g_label_refs[MAX_OPS];
static const struct parsed_proto *g_func_pp;
static struct parsed_data *g_func_pd;
static int g_func_pd_cnt;
static int g_func_lmods;
static char g_func[256];
static char g_comment[256];
static int g_bp_frame;
static int g_sp_frame;
static int g_stack_frame_used;
static int g_stack_fsz;
static int g_seh_found;
static int g_seh_size;
static int g_ida_func_attr;
static int g_sct_func_attr;
static int g_stack_clear_start; // in dwords
static int g_stack_clear_len;
static int g_regmask_init;
static int g_regmask_rm;
static int g_skip_func;
static int g_allow_regfunc;
static int g_allow_user_icall;
static int g_nowarn_reguse;
static int g_quiet_pp;
static int g_header_mode;

#define ferr(op_, fmt, ...) do { \
  printf("%s:%d: error %u: [%s] '%s': " fmt, asmfn, (op_)->asmln, \
    __LINE__, g_func, dump_op(op_), ##__VA_ARGS__); \
  fcloseall(); \
  exit(1); \
} while (0)
#define fnote(op_, fmt, ...) \
  printf("%s:%d: note: [%s] '%s': " fmt, asmfn, (op_)->asmln, g_func, \
    dump_op(op_), ##__VA_ARGS__)

#define ferr_assert(op_, cond) do { \
  if (!(cond)) ferr(op_, "assertion '%s' failed\n", #cond); \
} while (0)

#define IS_OP_INDIRECT_CALL(op_) \
  ((op_)->op == OP_CALL && (op_)->operand[0].type != OPT_LABEL)

const char *regs_r32[] = {
  "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
  // not r32, but list here for easy parsing and printing
  "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7",
  "st", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)"
};
const char *regs_r16[] = { "ax", "bx", "cx", "dx", "si", "di", "bp", "sp" };
const char *regs_r8l[] = { "al", "bl", "cl", "dl" };
const char *regs_r8h[] = { "ah", "bh", "ch", "dh" };

enum x86_regs {
  xUNSPEC = -1,
  xAX, xBX, xCX, xDX,
  xSI, xDI, xBP, xSP,
  xMM0, xMM1, xMM2, xMM3, // mmx
  xMM4, xMM5, xMM6, xMM7,
  xST0, xST1, xST2, xST3, // x87
  xST4, xST5, xST6, xST7,
};

#define mxAX     (1 << xAX)
#define mxBX     (1 << xBX)
#define mxCX     (1 << xCX)
#define mxDX     (1 << xDX)
#define mxSP     (1 << xSP)
#define mxST0    (1 << xST0)
#define mxST1    (1 << xST1)
#define mxST1_0  (mxST1 | mxST0)
#define mxST7_2  (0xfc << xST0)
#define mxSTa    (0xff << xST0)

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

#define PFOB_O   (1 << PFO_O)
#define PFOB_C   (1 << PFO_C)
#define PFOB_Z   (1 << PFO_Z)
#define PFOB_S   (1 << PFO_S)

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

static int check_segment_prefix(const char *s)
{
  if (s[0] == 0 || s[1] != 's' || s[2] != ':')
    return 0;

  switch (s[0]) {
  case 'c': return SEG_CS;
  case 'd': return SEG_DS;
  case 's': return SEG_SS;
  case 'e': return SEG_ES;
  case 'f': return SEG_FS;
  case 'g': return SEG_GS;
  default:  return 0;
  }
}

static int parse_reg(enum opr_lenmod *reg_lmod, const char *s)
{
  int reg;

  reg = char_array_i(regs_r32, ARRAY_SIZE(regs_r32), s);
  if (reg >= 8) {
    *reg_lmod = OPLM_QWORD;
    return reg;
  }
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

    // skip '?s:' prefixes
    if (check_segment_prefix(s))
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
      number = parse_number(w, 0);
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

static const char *parse_stack_el(const char *name, char *extra_reg,
  int *base_val, int early_try)
{
  const char *p, *p2, *s;
  char *endp = NULL;
  char buf[32];
  long val = -1;
  int len;

  if (g_bp_frame || early_try)
  {
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
  }

  if (!IS_START(name, "esp+"))
    return NULL;

  s = name + 4;
  p = strchr(s, '+');
  if (p) {
    if (is_reg_in_str(s)) {
      if (extra_reg != NULL) {
        strncpy(extra_reg, s, p - s);
        extra_reg[p - s] = 0;
      }
      s = p + 1;
      p = strchr(s, '+');
      if (p == NULL)
        aerr("%s IDA stackvar not set?\n", __func__);
    }
    if ('0' <= *s && *s <= '9') {
      if (s[0] == '0' && s[1] == 'x')
        s += 2;
      len = p - s;
      if (len < sizeof(buf) - 1) {
        strncpy(buf, s, len);
        buf[len] = 0;
        errno = 0;
        val = strtol(buf, &endp, 16);
        if (val == 0 || *endp != 0 || errno != 0) {
          aerr("%s num parse fail for '%s'\n", __func__, buf);
          return NULL;
        }
      }
      p++;
    }
    else {
      // probably something like [esp+arg_4+2]
      p = s;
      val = 0;
    }
  }
  else
    p = name + 4;

  if ('0' <= *p && *p <= '9')
    return NULL;

  if (base_val != NULL)
    *base_val = val;
  return p;
}

static int guess_lmod_from_name(struct parsed_opr *opr)
{
  if (IS_START(opr->name, "dword_") || IS_START(opr->name, "off_")) {
    opr->lmod = OPLM_DWORD;
    return 1;
  }
  if (IS_START(opr->name, "word_")) {
    opr->lmod = OPLM_WORD;
    return 1;
  }
  if (IS_START(opr->name, "byte_")) {
    opr->lmod = OPLM_BYTE;
    return 1;
  }
  if (IS_START(opr->name, "qword_")) {
    opr->lmod = OPLM_QWORD;
    return 1;
  }
  return 0;
}

static int guess_lmod_from_c_type(enum opr_lenmod *lmod,
  const struct parsed_type *c_type)
{
  static const char *qword_types[] = {
    "uint64_t", "int64_t", "__int64",
  };
  static const char *dword_types[] = {
    "uint32_t", "int", "_DWORD", "UINT_PTR", "DWORD",
    "WPARAM", "LPARAM", "UINT", "__int32",
    "LONG", "HIMC", "BOOL", "size_t",
    "float",
  };
  static const char *word_types[] = {
    "uint16_t", "int16_t", "_WORD", "WORD",
    "unsigned __int16", "__int16",
  };
  static const char *byte_types[] = {
    "uint8_t", "int8_t", "char",
    "unsigned __int8", "__int8", "BYTE", "_BYTE",
    "CHAR", "_UNKNOWN",
    // structures.. deal the same as with _UNKNOWN for now
    "CRITICAL_SECTION",
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

  for (i = 0; i < ARRAY_SIZE(qword_types); i++) {
    if (IS(n, qword_types[i])) {
      *lmod = OPLM_QWORD;
      return 1;
    }
  }

  return 0;
}

static char *default_cast_to(char *buf, size_t buf_size,
  struct parsed_opr *opr)
{
  buf[0] = 0;

  if (!opr->is_ptr || strchr(opr->name, '['))
    return buf;
  if (opr->pp == NULL || opr->pp->type.name == NULL
    || opr->pp->is_fptr)
  {
    snprintf(buf, buf_size, "%s", "(void *)");
    return buf;
  }

  snprintf(buf, buf_size, "(%s)", opr->pp->type.name);
  return buf;
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
  const struct parsed_proto *pp = NULL;
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
      ret = check_segment_prefix(label);
      if (ret != 0) {
        opr->segment = ret;
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
      else if (IS(words[w], "qword"))
        opr->lmod = OPLM_QWORD;
      else
        aerr("type parsing failed\n");
      w += 2;
      wordc_in = wordc - w;
    }
  }

  if (wordc_in == 2) {
    if (IS(words[w], "offset")) {
      opr->type = OPT_OFFSET;
      opr->lmod = OPLM_DWORD;
      strcpy(opr->name, words[w + 1]);
      pp = proto_parse(g_fhdr, opr->name, 1);
      goto do_label;
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

  ret = check_segment_prefix(words[w]);
  if (ret != 0) {
    opr->segment = ret;
    memmove(words[w], words[w] + 3, strlen(words[w]) - 2);
    if (ret == SEG_FS && IS(words[w], "0"))
      g_seh_found = 1;
  }
  strcpy(opr->name, words[w]);

  if (words[w][0] == '[') {
    opr->type = OPT_REGMEM;
    ret = sscanf(words[w], "[%[^]]]", opr->name);
    if (ret != 1)
      aerr("[] parse failure\n");

    parse_indmode(opr->name, regmask_indirect, 1);
    if (opr->lmod == OPLM_UNSPEC
      && parse_stack_el(opr->name, NULL, NULL, 1))
    {
      // might be an equ
      struct parsed_equ *eq =
        equ_find(NULL, parse_stack_el(opr->name, NULL, NULL, 1), &i);
      if (eq)
        opr->lmod = eq->lmod;

      // might be unaligned access
      g_func_lmods |= 1 << OPLM_BYTE;
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
    number = parse_number(words[w], 0);
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
  pp = proto_parse(g_fhdr, opr->name, g_quiet_pp);

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
  opr->pp = pp;

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
  { "lock",   OPF_LOCK },
};

#define OPF_CJMP_CC (OPF_JMP|OPF_CJMP|OPF_CC)

static const struct {
  const char *name;
  enum op_op op;
  unsigned short minopr;
  unsigned short maxopr;
  unsigned int flags;
  unsigned char pfo;
  unsigned char pfo_inv;
} op_table[] = {
  { "nop",  OP_NOP,    0, 0, 0 },
  { "push", OP_PUSH,   1, 1, 0 },
  { "pop",  OP_POP,    1, 1, OPF_DATA },
  { "pusha",OP_PUSHA,  0, 0, 0 },
  { "popa", OP_POPA,   0, 0, OPF_DATA },
  { "leave",OP_LEAVE,  0, 0, OPF_DATA },
  { "mov" , OP_MOV,    2, 2, OPF_DATA },
  { "lea",  OP_LEA,    2, 2, OPF_DATA },
  { "movzx",OP_MOVZX,  2, 2, OPF_DATA },
  { "movsx",OP_MOVSX,  2, 2, OPF_DATA },
  { "xchg", OP_XCHG,   2, 2, OPF_DATA },
  { "not",  OP_NOT,    1, 1, OPF_DATA },
  { "xlat", OP_XLAT,   0, 0, OPF_DATA },
  { "cdq",  OP_CDQ,    0, 0, OPF_DATA },
  { "bswap",OP_BSWAP,  1, 1, OPF_DATA },
  { "lodsb",OP_LODS,   0, 0, OPF_DATA },
  { "lodsw",OP_LODS,   0, 0, OPF_DATA },
  { "lodsd",OP_LODS,   0, 0, OPF_DATA },
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
  { "rdtsc",OP_RDTSC,  0, 0, OPF_DATA },
  { "cpuid",OP_CPUID,  0, 0, OPF_DATA },
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
  { "shld", OP_SHLD,   3, 3, OPF_DATA|OPF_FLAGS },
  { "shrd", OP_SHRD,   3, 3, OPF_DATA|OPF_FLAGS },
  { "rol",  OP_ROL,    2, 2, OPF_DATA|OPF_FLAGS },
  { "ror",  OP_ROR,    2, 2, OPF_DATA|OPF_FLAGS },
  { "rcl",  OP_RCL,    2, 2, OPF_DATA|OPF_FLAGS|OPF_CC, PFO_C },
  { "rcr",  OP_RCR,    2, 2, OPF_DATA|OPF_FLAGS|OPF_CC, PFO_C },
  { "adc",  OP_ADC,    2, 2, OPF_DATA|OPF_FLAGS|OPF_CC, PFO_C },
  { "sbb",  OP_SBB,    2, 2, OPF_DATA|OPF_FLAGS|OPF_CC, PFO_C },
  { "bsf",  OP_BSF,    2, 2, OPF_DATA|OPF_FLAGS },
  { "bsr",  OP_BSR,    2, 2, OPF_DATA|OPF_FLAGS },
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
  { "loop", OP_LOOP,   1, 1, OPF_JMP|OPF_CJMP|OPF_DATA },
  { "jo",   OP_JCC,    1, 1, OPF_CJMP_CC, PFO_O,  0 }, // 70 OF=1
  { "jno",  OP_JCC,    1, 1, OPF_CJMP_CC, PFO_O,  1 }, // 71 OF=0
  { "jc",   OP_JCC,    1, 1, OPF_CJMP_CC, PFO_C,  0 }, // 72 CF=1
  { "jb",   OP_JCC,    1, 1, OPF_CJMP_CC, PFO_C,  0 }, // 72
  { "jnc",  OP_JCC,    1, 1, OPF_CJMP_CC, PFO_C,  1 }, // 73 CF=0
  { "jnb",  OP_JCC,    1, 1, OPF_CJMP_CC, PFO_C,  1 }, // 73
  { "jae",  OP_JCC,    1, 1, OPF_CJMP_CC, PFO_C,  1 }, // 73
  { "jz",   OP_JCC,    1, 1, OPF_CJMP_CC, PFO_Z,  0 }, // 74 ZF=1
  { "je",   OP_JCC,    1, 1, OPF_CJMP_CC, PFO_Z,  0 }, // 74
  { "jnz",  OP_JCC,    1, 1, OPF_CJMP_CC, PFO_Z,  1 }, // 75 ZF=0
  { "jne",  OP_JCC,    1, 1, OPF_CJMP_CC, PFO_Z,  1 }, // 75
  { "jbe",  OP_JCC,    1, 1, OPF_CJMP_CC, PFO_BE, 0 }, // 76 CF=1||ZF=1
  { "jna",  OP_JCC,    1, 1, OPF_CJMP_CC, PFO_BE, 0 }, // 76
  { "ja",   OP_JCC,    1, 1, OPF_CJMP_CC, PFO_BE, 1 }, // 77 CF=0&&ZF=0
  { "jnbe", OP_JCC,    1, 1, OPF_CJMP_CC, PFO_BE, 1 }, // 77
  { "js",   OP_JCC,    1, 1, OPF_CJMP_CC, PFO_S,  0 }, // 78 SF=1
  { "jns",  OP_JCC,    1, 1, OPF_CJMP_CC, PFO_S,  1 }, // 79 SF=0
  { "jp",   OP_JCC,    1, 1, OPF_CJMP_CC, PFO_P,  0 }, // 7a PF=1
  { "jpe",  OP_JCC,    1, 1, OPF_CJMP_CC, PFO_P,  0 }, // 7a
  { "jnp",  OP_JCC,    1, 1, OPF_CJMP_CC, PFO_P,  1 }, // 7b PF=0
  { "jpo",  OP_JCC,    1, 1, OPF_CJMP_CC, PFO_P,  1 }, // 7b
  { "jl",   OP_JCC,    1, 1, OPF_CJMP_CC, PFO_L,  0 }, // 7c SF!=OF
  { "jnge", OP_JCC,    1, 1, OPF_CJMP_CC, PFO_L,  0 }, // 7c
  { "jge",  OP_JCC,    1, 1, OPF_CJMP_CC, PFO_L,  1 }, // 7d SF=OF
  { "jnl",  OP_JCC,    1, 1, OPF_CJMP_CC, PFO_L,  1 }, // 7d
  { "jle",  OP_JCC,    1, 1, OPF_CJMP_CC, PFO_LE, 0 }, // 7e ZF=1||SF!=OF
  { "jng",  OP_JCC,    1, 1, OPF_CJMP_CC, PFO_LE, 0 }, // 7e
  { "jg",   OP_JCC,    1, 1, OPF_CJMP_CC, PFO_LE, 1 }, // 7f ZF=0&&SF=OF
  { "jnle", OP_JCC,    1, 1, OPF_CJMP_CC, PFO_LE, 1 }, // 7f
  { "seto",   OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_O,  0 },
  { "setno",  OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_O,  1 },
  { "setc",   OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_C,  0 },
  { "setb",   OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_C,  0 },
  { "setnc",  OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_C,  1 },
  { "setae",  OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_C,  1 },
  { "setnb",  OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_C,  1 },
  { "setz",   OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_Z,  0 },
  { "sete",   OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_Z,  0 },
  { "setnz",  OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_Z,  1 },
  { "setne",  OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_Z,  1 },
  { "setbe",  OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_BE, 0 },
  { "setna",  OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_BE, 0 },
  { "seta",   OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_BE, 1 },
  { "setnbe", OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_BE, 1 },
  { "sets",   OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_S,  0 },
  { "setns",  OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_S,  1 },
  { "setp",   OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_P,  0 },
  { "setpe",  OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_P,  0 },
  { "setnp",  OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_P,  1 },
  { "setpo",  OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_P,  1 },
  { "setl",   OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_L,  0 },
  { "setnge", OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_L,  0 },
  { "setge",  OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_L,  1 },
  { "setnl",  OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_L,  1 },
  { "setle",  OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_LE, 0 },
  { "setng",  OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_LE, 0 },
  { "setg",   OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_LE, 1 },
  { "setnle", OP_SCC,  1, 1, OPF_DATA|OPF_CC, PFO_LE, 1 },
  // x87
  { "fld",    OP_FLD,    1, 1, OPF_FPUSH },
  { "fild",   OP_FILD,   1, 1, OPF_FPUSH|OPF_FINT },
  { "fld1",   OP_FLDc,   0, 0, OPF_FPUSH },
  { "fldl2t", OP_FLDc,   0, 0, OPF_FPUSH },
  { "fldl2e", OP_FLDc,   0, 0, OPF_FPUSH },
  { "fldpi",  OP_FLDc,   0, 0, OPF_FPUSH },
  { "fldlg2", OP_FLDc,   0, 0, OPF_FPUSH },
  { "fldln2", OP_FLDc,   0, 0, OPF_FPUSH },
  { "fldz",   OP_FLDc,   0, 0, OPF_FPUSH },
  { "fst",    OP_FST,    1, 1, 0 },
  { "fstp",   OP_FST,    1, 1, OPF_FPOP },
  { "fist",   OP_FIST,   1, 1, OPF_FINT },
  { "fistp",  OP_FIST,   1, 1, OPF_FPOP|OPF_FINT },
  { "fabs",   OP_FABS,   0, 0, 0 },
  { "fadd",   OP_FADD,   0, 2, 0 },
  { "faddp",  OP_FADD,   0, 2, OPF_FPOP },
  { "fdiv",   OP_FDIV,   0, 2, 0 },
  { "fdivp",  OP_FDIV,   0, 2, OPF_FPOP },
  { "fmul",   OP_FMUL,   0, 2, 0 },
  { "fmulp",  OP_FMUL,   0, 2, OPF_FPOP },
  { "fsub",   OP_FSUB,   0, 2, 0 },
  { "fsubp",  OP_FSUB,   0, 2, OPF_FPOP },
  { "fdivr",  OP_FDIVR,  0, 2, 0 },
  { "fdivrp", OP_FDIVR,  0, 2, OPF_FPOP },
  { "fsubr",  OP_FSUBR,  0, 2, 0 },
  { "fsubrp", OP_FSUBR,  0, 2, OPF_FPOP },
  { "fiadd",  OP_FIADD,  1, 1, OPF_FINT },
  { "fidiv",  OP_FIDIV,  1, 1, OPF_FINT },
  { "fimul",  OP_FIMUL,  1, 1, OPF_FINT },
  { "fisub",  OP_FISUB,  1, 1, OPF_FINT },
  { "fidivr", OP_FIDIVR, 1, 1, OPF_FINT },
  { "fisubr", OP_FISUBR, 1, 1, OPF_FINT },
  { "fcom",   OP_FCOM,   0, 1, 0 },
  { "fcomp",  OP_FCOM,   0, 1, OPF_FPOP },
  { "fcompp", OP_FCOM,   0, 0, OPF_FPOPP },
  { "fucom",  OP_FCOM,   0, 1, 0 },
  { "fucomp", OP_FCOM,   0, 1, OPF_FPOP },
  { "fucompp",OP_FCOM,   0, 0, OPF_FPOPP },
  { "fnstsw", OP_FNSTSW, 1, 1, OPF_DATA },
  { "fchs",   OP_FCHS,   0, 0, 0 },
  { "fcos",   OP_FCOS,   0, 0, 0 },
  { "fpatan", OP_FPATAN, 0, 0, OPF_FPOP },
  { "fptan",  OP_FPTAN,  0, 0, OPF_FPUSH },
  { "fsin",   OP_FSIN,   0, 0, 0 },
  { "fsqrt",  OP_FSQRT,  0, 0, 0 },
  { "fxch",   OP_FXCH,   1, 1, 0 },
  { "fyl2x",  OP_FYL2X,  0, 0, OPF_FPOP },
  // mmx
  { "emms",   OP_EMMS,   0, 0, OPF_DATA },
  { "movq",   OP_MOV,    2, 2, OPF_DATA },
  // pseudo-ops for lib calls
  { "_allshl",OPP_ALLSHL },
  { "_allshr",OPP_ALLSHR },
  { "_ftol",  OPP_FTOL },
  { "_CIpow", OPP_CIPOW },
  { "abort",  OPP_ABORT },
  // must be last
  { "ud2",    OP_UD2 },
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
  int i, j;

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

  if (i == ARRAY_SIZE(op_table)) {
    if (!g_skip_func)
      aerr("unhandled op: '%s'\n", words[0]);
    i--; // OP_UD2
  }
  w++;

  op->op = op_table[i].op;
  op->flags = op_table[i].flags | prefix_flags;
  op->pfo = op_table[i].pfo;
  op->pfo_inv = op_table[i].pfo_inv;
  op->regmask_src = op->regmask_dst = 0;
  op->asmln = asmln;

  if (op->op == OP_UD2)
    return;

  for (opr = 0; opr < op_table[i].maxopr; opr++) {
    if (opr >= op_table[i].minopr && w >= wordc)
      break;

    regmask = regmask_ind = 0;
    w = parse_operand(&op->operand[opr], &regmask, &regmask_ind,
      words, wordc, w, op->flags);

    if (opr == 0 && (op->flags & OPF_DATA))
      op->regmask_dst = regmask;
    else
      op->regmask_src |= regmask;
    op->regmask_src |= regmask_ind;

    if (op->operand[opr].lmod != OPLM_UNSPEC)
      g_func_lmods |= 1 << op->operand[opr].lmod;
  }

  if (w < wordc)
    aerr("parse_op %s incomplete: %d/%d\n",
      words[0], w, wordc);

  // special cases
  op->operand_cnt = opr;
  if (!strncmp(op_table[i].name, "set", 3))
    op->operand[0].lmod = OPLM_BYTE;

  switch (op->op) {
  // first operand is not dst
  case OP_CMP:
  case OP_TEST:
    op->regmask_src |= op->regmask_dst;
    op->regmask_dst = 0;
    break;

  // first operand is src too
  case OP_NOT:
  case OP_ADD:
  case OP_AND:
  case OP_OR:
  case OP_RCL:
  case OP_RCR:
  case OP_ADC:
  case OP_INC:
  case OP_DEC:
  case OP_NEG:
  case OP_BSWAP:
  // more below..
    op->regmask_src |= op->regmask_dst;
    break;

  // special
  case OP_XCHG:
    op->regmask_src |= op->regmask_dst;
    op->regmask_dst |= op->regmask_src;
    goto check_align;

  case OP_SUB:
  case OP_SBB:
  case OP_XOR:
    if (op->operand[0].type == OPT_REG && op->operand[1].type == OPT_REG
     && op->operand[0].lmod == op->operand[1].lmod
     && op->operand[0].reg == op->operand[1].reg
     && IS(op->operand[0].name, op->operand[1].name)) // ! ah, al..
    {
      op->regmask_src = 0;
    }
    else
      op->regmask_src |= op->regmask_dst;
    break;

  // ops with implicit argumets
  case OP_XLAT:
    op->operand_cnt = 2;
    setup_reg_opr(&op->operand[0], xAX, OPLM_BYTE, &op->regmask_src);
    op->regmask_dst = op->regmask_src;
    setup_reg_opr(&op->operand[1], xBX, OPLM_DWORD, &op->regmask_src);
    break;

  case OP_CDQ:
    op->operand_cnt = 2;
    setup_reg_opr(&op->operand[0], xDX, OPLM_DWORD, &op->regmask_dst);
    setup_reg_opr(&op->operand[1], xAX, OPLM_DWORD, &op->regmask_src);
    break;

  case OP_LODS:
  case OP_STOS:
  case OP_SCAS:
    if      (words[op_w][4] == 'b')
      lmod = OPLM_BYTE;
    else if (words[op_w][4] == 'w')
      lmod = OPLM_WORD;
    else if (words[op_w][4] == 'd')
      lmod = OPLM_DWORD;
    j = 0;
    op->regmask_src = 0;
    setup_reg_opr(&op->operand[j++], op->op == OP_LODS ? xSI : xDI,
      OPLM_DWORD, &op->regmask_src);
    op->regmask_dst = op->regmask_src;
    setup_reg_opr(&op->operand[j++], xAX, lmod,
      op->op == OP_LODS ? &op->regmask_dst : &op->regmask_src);
    if (op->flags & OPF_REP) {
      setup_reg_opr(&op->operand[j++], xCX, OPLM_DWORD, &op->regmask_src);
      op->regmask_dst |= 1 << xCX;
    }
    op->operand_cnt = j;
    break;

  case OP_MOVS:
  case OP_CMPS:
    if      (words[op_w][4] == 'b')
      lmod = OPLM_BYTE;
    else if (words[op_w][4] == 'w')
      lmod = OPLM_WORD;
    else if (words[op_w][4] == 'd')
      lmod = OPLM_DWORD;
    j = 0;
    op->regmask_src = 0;
    // note: lmod is not correct, don't have where to place it
    setup_reg_opr(&op->operand[j++], xDI, lmod, &op->regmask_src);
    setup_reg_opr(&op->operand[j++], xSI, OPLM_DWORD, &op->regmask_src);
    if (op->flags & OPF_REP)
      setup_reg_opr(&op->operand[j++], xCX, OPLM_DWORD, &op->regmask_src);
    op->operand_cnt = j;
    op->regmask_dst = op->regmask_src;
    break;

  case OP_RDTSC:
    op->regmask_dst = mxAX | mxDX;
    break;

  case OP_CPUID:
    // for now, ignore ecx dep for eax={4,7,b,d}
    op->regmask_src = mxAX;
    op->regmask_dst = mxAX | mxBX | mxCX | mxDX;
    break;

  case OP_LOOP:
    op->regmask_dst = 1 << xCX;
    // fallthrough
  case OP_JECXZ:
    op->operand_cnt = 2;
    op->regmask_src = 1 << xCX;
    op->operand[1].type = OPT_REG;
    op->operand[1].reg = xCX;
    op->operand[1].lmod = OPLM_DWORD;
    break;

  case OP_IMUL:
    if (op->operand_cnt == 2) {
      if (op->operand[0].type != OPT_REG)
        aerr("reg expected\n");
      op->regmask_src |= 1 << op->operand[0].reg;
    }
    if (op->operand_cnt != 1)
      break;
    // fallthrough
  case OP_MUL:
    // singleop mul
    if (op->operand[0].lmod == OPLM_UNSPEC)
      op->operand[0].lmod = OPLM_DWORD;
    op->regmask_src = mxAX | op->regmask_dst;
    op->regmask_dst = mxAX;
    if (op->operand[0].lmod != OPLM_BYTE)
      op->regmask_dst |= mxDX;
    break;

  case OP_DIV:
  case OP_IDIV:
    // we could set up operands for edx:eax, but there is no real need to
    // (see is_opr_modified())
    if (op->operand[0].lmod == OPLM_UNSPEC)
      op->operand[0].lmod = OPLM_DWORD;
    op->regmask_src = mxAX | op->regmask_dst;
    op->regmask_dst = mxAX;
    if (op->operand[0].lmod != OPLM_BYTE) {
      op->regmask_src |= mxDX;
      op->regmask_dst |= mxDX;
    }
    break;

  case OP_SHL:
  case OP_SHR:
  case OP_SAR:
  case OP_ROL:
  case OP_ROR:
    op->regmask_src |= op->regmask_dst;
    if (op->operand[1].lmod == OPLM_UNSPEC)
      op->operand[1].lmod = OPLM_BYTE;
    break;

  case OP_SHLD:
  case OP_SHRD:
    op->regmask_src |= op->regmask_dst;
    if (op->operand[2].lmod == OPLM_UNSPEC)
      op->operand[2].lmod = OPLM_BYTE;
    break;

  case OP_PUSH:
    op->regmask_src |= op->regmask_dst;
    op->regmask_dst = 0;
    if (op->operand[0].lmod == OPLM_UNSPEC
        && (op->operand[0].type == OPT_CONST
         || op->operand[0].type == OPT_OFFSET
         || op->operand[0].type == OPT_LABEL))
      op->operand[0].lmod = OPLM_DWORD;
    break;

  // alignment
  case OP_MOV:
  check_align:
    if (op->operand[0].type == OPT_REG && op->operand[1].type == OPT_REG
     && op->operand[0].lmod == op->operand[1].lmod
     && op->operand[0].reg == op->operand[1].reg
     && IS(op->operand[0].name, op->operand[1].name)) // ! ah, al..
    {
      op->flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
      op->regmask_src = op->regmask_dst = 0;
    }
    break;

  case OP_LEA:
    if (op->operand[0].type == OPT_REG
     && op->operand[1].type == OPT_REGMEM)
    {
      char buf[16];
      snprintf(buf, sizeof(buf), "%s+0", op->operand[0].name);
      if (IS(buf, op->operand[1].name))
        op->flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
    }
    break;

  case OP_CALL:
    // needed because of OPF_DATA
    op->regmask_src |= op->regmask_dst;
    // trashed regs must be explicitly detected later
    op->regmask_dst = 0;
    break;

  case OP_LEAVE:
    op->regmask_dst = (1 << xBP) | (1 << xSP);
    op->regmask_src =  1 << xBP;
    break;

  case OP_FLD:
  case OP_FILD:
    op->regmask_dst |= mxST0;
    break;

  case OP_FLDc:
    op->regmask_dst |= mxST0;
    if      (IS(words[op_w] + 3, "1"))
      op->operand[0].val = X87_CONST_1;
    else if (IS(words[op_w] + 3, "l2t"))
      op->operand[0].val = X87_CONST_L2T;
    else if (IS(words[op_w] + 3, "l2e"))
      op->operand[0].val = X87_CONST_L2E;
    else if (IS(words[op_w] + 3, "pi"))
      op->operand[0].val = X87_CONST_PI;
    else if (IS(words[op_w] + 3, "lg2"))
      op->operand[0].val = X87_CONST_LG2;
    else if (IS(words[op_w] + 3, "ln2"))
      op->operand[0].val = X87_CONST_LN2;
    else if (IS(words[op_w] + 3, "z"))
      op->operand[0].val = X87_CONST_Z;
    else
      aerr("fld what?\n");
    break;

  case OP_FST:
  case OP_FIST:
    op->regmask_src |= mxST0;
    break;

  case OP_FADD:
  case OP_FDIV:
  case OP_FMUL:
  case OP_FSUB:
  case OP_FDIVR:
  case OP_FSUBR:
    op->regmask_src |= mxST0;
    if (op->operand_cnt == 2)
      op->regmask_src |= op->regmask_dst;
    else if (op->operand_cnt == 1) {
      memcpy(&op->operand[1], &op->operand[0], sizeof(op->operand[1]));
      op->operand[0].type = OPT_REG;
      op->operand[0].lmod = OPLM_QWORD;
      op->operand[0].reg = xST0;
      op->regmask_dst |= mxST0;
    }
    else
      // IDA doesn't use this
      aerr("no operands?\n");
    break;

  case OP_FIADD:
  case OP_FIDIV:
  case OP_FIMUL:
  case OP_FISUB:
  case OP_FIDIVR:
  case OP_FISUBR:
  case OP_FABS:
  case OP_FCHS:
  case OP_FCOS:
  case OP_FSIN:
  case OP_FSQRT:
  case OP_FXCH:
    op->regmask_src |= mxST0;
    op->regmask_dst |= mxST0;
    break;

  case OP_FPATAN:
  case OP_FYL2X:
    op->regmask_src |= mxST0 | mxST1;
    op->regmask_dst |= mxST0;
    break;

  case OP_FPTAN:
    aerr("TODO\n");
    break;

  case OP_FCOM:
    op->regmask_src |= mxST0;
    if (op->operand_cnt == 0) {
      op->operand_cnt = 1;
      op->operand[0].type = OPT_REG;
      op->operand[0].lmod = OPLM_QWORD;
      op->operand[0].reg = xST1;
      op->regmask_src |= mxST1;
    }
    break;

  default:
    break;
  }

  if (op->operand[0].type == OPT_REG
   && op->operand[1].type == OPT_CONST)
  {
    struct parsed_opr *op1 = &op->operand[1];
    if ((op->op == OP_AND && op1->val == 0)
     || (op->op == OP_OR
      && (op1->val == ~0
       || (op->operand[0].lmod == OPLM_WORD && op1->val == 0xffff)
       || (op->operand[0].lmod == OPLM_BYTE && op1->val == 0xff))))
    {
      op->regmask_src = 0;
    }
  }
}

static const char *op_name(struct parsed_op *po)
{
  static char buf[16];
  char *p;
  int i;

  if (po->op == OP_JCC || po->op == OP_SCC) {
    p = buf;
    *p++ = (po->op == OP_JCC) ? 'j' : 's';
    if (po->pfo_inv)
      *p++ = 'n';
    strcpy(p, parsed_flag_op_names[po->pfo]);
    return buf;
  }

  for (i = 0; i < ARRAY_SIZE(op_table); i++)
    if (op_table[i].op == po->op)
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

  snprintf(out, sizeof(out), "%s", op_name(po));
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
  case OPLM_QWORD:
    return "u64";
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
  case OPLM_QWORD:
    return "";
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
  case OPLM_QWORD:
    return "*(u64 *)";
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
  case OPLM_QWORD:
    return "(s64)";
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
  case OPLM_QWORD:
    return 8;
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
  if ((unsigned int)popr->reg >= ARRAY_SIZE(regs_r32))
    ferr(po, "invalid reg: %d\n", popr->reg);
  return regs_r32[popr->reg];
}

static int check_simple_cast(const char *cast, int *bits, int *is_signed)
{
  if      (IS_START(cast, "(s8)") || IS_START(cast, "(u8)"))
    *bits = 8;
  else if (IS_START(cast, "(s16)") || IS_START(cast, "(u16)"))
    *bits = 16;
  else if (IS_START(cast, "(s32)") || IS_START(cast, "(u32)"))
    *bits = 32;
  else if (IS_START(cast, "(s64)") || IS_START(cast, "(u64)"))
    *bits = 64;
  else
    return -1;

  *is_signed = cast[1] == 's' ? 1 : 0;
  return 0;
}

static int check_deref_cast(const char *cast, int *bits)
{
  if      (IS_START(cast, "*(u8 *)"))
    *bits = 8;
  else if (IS_START(cast, "*(u16 *)"))
    *bits = 16;
  else if (IS_START(cast, "*(u32 *)"))
    *bits = 32;
  else if (IS_START(cast, "*(u64 *)"))
    *bits = 64;
  else
    return -1;

  return 0;
}

// cast1 is the "final" cast
static const char *simplify_cast(const char *cast1, const char *cast2)
{
  static char buf[256];
  int bits1, bits2;
  int s1, s2;

  if (cast1[0] == 0)
    return cast2;
  if (cast2[0] == 0)
    return cast1;
  if (IS(cast1, cast2))
    return cast1;

  if (check_simple_cast(cast1, &bits1, &s1) == 0
    && check_simple_cast(cast2, &bits2, &s2) == 0)
  {
    if (bits1 <= bits2)
      return cast1;
  }
  if (check_simple_cast(cast1, &bits1, &s1) == 0
    && check_deref_cast(cast2, &bits2) == 0)
  {
    if (bits1 == bits2) {
      snprintf(buf, sizeof(buf), "*(%c%d *)", s1 ? 's' : 'u', bits1);
      return buf;
    }
  }

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

  p = strpbrk(name, "+-");
  if (p != NULL) {
    namelen = p - name;
    if (namelen <= 0)
      ferr(po, "equ parse failed for '%s'\n", name);

    errno = 0;
    *extra_offs = strtol(p, &endp, 16);
    if (*endp != 0 || errno != 0)
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
  return (parse_stack_el(popr->name, NULL, NULL, 0)
    || (g_bp_frame && !(po->flags & OPF_EBP_S)
        && IS_START(popr->name, "ebp")));
}

static void parse_stack_access(struct parsed_op *po,
  const char *name, char *ofs_reg, int *offset_out,
  int *stack_ra_out, const char **bp_arg_out, int is_lea)
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
    errno = 0;
    offset = strtoul(p, &endp, 16);
    if (name[3] == '-')
      offset = -offset;
    if (*endp != 0 || errno != 0)
      ferr(po, "ebp- parse of '%s' failed\n", name);
  }
  else {
    bp_arg = parse_stack_el(name, ofs_reg, NULL, 0);
    eq = equ_find(po, bp_arg, &offset);
    if (eq == NULL)
      ferr(po, "detected but missing eq\n");
    offset += eq->offset;
  }

  if (!strncmp(name, "ebp", 3))
    stack_ra = 4;

  // yes it sometimes LEAs ra for compares..
  if (!is_lea && ofs_reg[0] == 0
    && stack_ra <= offset && offset < stack_ra + 4)
  {
    ferr(po, "reference to ra? %d %d\n", offset, stack_ra);
  }

  *offset_out = offset;
  if (stack_ra_out)
    *stack_ra_out = stack_ra;
  if (bp_arg_out)
    *bp_arg_out = bp_arg;
}

static int parse_stack_esp_offset(struct parsed_op *po,
  const char *name, int *offset_out)
{
  char ofs_reg[16] = { 0, };
  struct parsed_equ *eq;
  const char *bp_arg;
  char *endp = NULL;
  int base_val = 0;
  int offset = 0;

  if (strstr(name, "esp") == NULL)
    return -1;
  bp_arg = parse_stack_el(name, ofs_reg, &base_val, 0);
  if (bp_arg == NULL) {
    // just plain offset?
    if (!IS_START(name, "esp+"))
      return -1;
    errno = 0;
    offset = strtol(name + 4, &endp, 0);
    if (endp == NULL || *endp != 0 || errno != 0)
      return -1;
    *offset_out = offset;
    return 0;
  }

  if (ofs_reg[0] != 0)
    return -1;
  eq = equ_find(po, bp_arg, &offset);
  if (eq == NULL)
    ferr(po, "detected but missing eq\n");
  offset += eq->offset;
  *offset_out = base_val + offset;
  return 0;
}

// returns g_func_pp arg number if arg is accessed
// -1 otherwise (stack vars, va_list)
// note: 'popr' must be from 'po', not some other op
static int stack_frame_access(struct parsed_op *po,
  struct parsed_opr *popr, char *buf, size_t buf_size,
  const char *name, const char *cast, int is_src, int is_lea)
{
  enum opr_lenmod tmp_lmod = OPLM_UNSPEC;
  const char *prefix = "";
  const char *bp_arg = NULL;
  char ofs_reg[16] = { 0, };
  char argname[8], buf2[32];
  int i, arg_i, arg_s;
  int unaligned = 0;
  int stack_ra = 0;
  int offset = 0;
  int retval = -1;
  int sf_ofs;

  if (g_bp_frame && (po->flags & OPF_EBP_S)
      && !(po->regmask_src & mxSP))
    ferr(po, "stack_frame_access while ebp is scratch\n");

  parse_stack_access(po, name, ofs_reg, &offset,
    &stack_ra, &bp_arg, is_lea);

  snprintf(g_comment, sizeof(g_comment), "%s", bp_arg);

  if (offset > stack_ra)
  {
    arg_i = (offset - stack_ra - 4) / 4;
    if (arg_i < 0 || arg_i >= g_func_pp->argc_stack)
    {
      if (g_func_pp->is_vararg && arg_i >= g_func_pp->argc_stack) {
        // vararg access - messy and non-portable,
        // but works with gcc on both x86 and ARM
        if (arg_i == g_func_pp->argc_stack)
          // should be va_list
          snprintf(buf2, sizeof(buf2), "*(u32 *)&ap");
        else
          snprintf(buf2, sizeof(buf2), "(*(u32 *)&ap + %u)",
            (arg_i - g_func_pp->argc_stack) * 4);

        if (is_lea)
          snprintf(buf, buf_size, "%s%s", cast, buf2);
        else
          snprintf(buf, buf_size, "%s*(u32 *)%s", cast, buf2);
        return -1;
      }
      ferr(po, "offset 0x%x (%s,%d) doesn't map to any arg\n",
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
    retval = i;

    snprintf(argname, sizeof(argname), "%sa%d",
      g_sct_func_attr & SCTFA_ARGFRAME ? "af." : "", i + 1);

    switch (popr->lmod)
    {
    case OPLM_BYTE:
      if (is_lea)
        ferr(po, "lea/byte to arg?\n");
      if (is_src && (offset & 3) == 0)
        snprintf(buf, buf_size, "%s%s",
          simplify_cast(cast, "(u8)"), argname);
      else
        snprintf(buf, buf_size, "%sBYTE%d(%s)",
          cast, offset & 3, argname);
      break;

    case OPLM_WORD:
      if (is_lea)
        ferr(po, "lea/word to arg?\n");
      if (offset & 1) {
        unaligned = 1;
        if (!is_src) {
          if (offset & 2)
            ferr(po, "problematic arg store\n");
          snprintf(buf, buf_size, "%s((char *)&%s + 1)",
            simplify_cast(cast, "*(u16 *)"), argname);
        }
        else
          ferr(po, "unaligned arg word load\n");
      }
      else if (is_src && (offset & 2) == 0)
        snprintf(buf, buf_size, "%s%s",
          simplify_cast(cast, "(u16)"), argname);
      else
        snprintf(buf, buf_size, "%s%sWORD(%s)",
          cast, (offset & 2) ? "HI" : "LO", argname);
      break;

    case OPLM_DWORD:
      if (cast[0])
        prefix = cast;
      else if (is_src)
        prefix = "(u32)";

      if (offset & 3) {
        unaligned = 1;
        if (is_lea)
          snprintf(buf, buf_size, "(u32)&%s + %d",
            argname, offset & 3);
        else if (!is_src)
          ferr(po, "unaligned arg store\n");
        else {
          // mov edx, [ebp+arg_4+2]; movsx ecx, dx
          snprintf(buf, buf_size, "%s(%s >> %d)",
            prefix, argname, (offset & 3) * 8);
        }
      }
      else {
        snprintf(buf, buf_size, "%s%s%s",
          prefix, is_lea ? "&" : "", argname);
      }
      break;

    case OPLM_QWORD:
      ferr_assert(po, !(offset & 7));
      if (cast[0])
        prefix = cast;
      snprintf(buf, buf_size, "%s%s%s",
        prefix, is_lea ? "&" : "", argname);
      break;

    default:
      ferr(po, "bp_arg bad lmod: %d\n", popr->lmod);
    }

    if (unaligned)
      strcat(g_comment, " unaligned");

    // common problem
    guess_lmod_from_c_type(&tmp_lmod, &g_func_pp->arg[i].type);
    if (tmp_lmod != OPLM_DWORD
      && (unaligned || (!is_src && lmod_bytes(po, tmp_lmod)
                         < lmod_bytes(po, popr->lmod) + (offset & 3))))
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
    if (ofs_reg[0] == 0 && (offset > 0 || sf_ofs < 0))
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

    case OPLM_QWORD:
      ferr_assert(po, !(sf_ofs & 7));
      ferr_assert(po, ofs_reg[0] == 0);
      // only used for x87 int64/float, float sets is_lea
      if (!is_lea && (po->flags & OPF_FINT))
        prefix = "*(s64 *)&";
      snprintf(buf, buf_size, "%ssf.q[%d]", prefix, sf_ofs / 8);
      break;

    default:
      ferr(po, "bp_stack bad lmod: %d\n", popr->lmod);
    }
  }

  return retval;
}

static void check_func_pp(struct parsed_op *po,
  const struct parsed_proto *pp, const char *pfx)
{
  enum opr_lenmod tmp_lmod;
  char buf[256];
  int ret, i;

  if (pp->argc_reg != 0) {
    if (!g_allow_user_icall && !pp->is_fastcall) {
      pp_print(buf, sizeof(buf), pp);
      ferr(po, "%s: unexpected reg arg in icall: %s\n", pfx, buf);
    }
    if (pp->argc_stack > 0 && pp->argc_reg != 2)
      ferr(po, "%s: %d reg arg(s) with %d stack arg(s)\n",
        pfx, pp->argc_reg, pp->argc_stack);
  }

  // fptrs must use 32bit args, callsite might have no information and
  // lack a cast to smaller types, which results in incorrectly masked
  // args passed (callee may assume masked args, it does on ARM)
  if (!pp->is_osinc) {
    for (i = 0; i < pp->argc; i++) {
      ret = guess_lmod_from_c_type(&tmp_lmod, &pp->arg[i].type);
      if (ret && tmp_lmod != OPLM_DWORD)
        ferr(po, "reference to %s with arg%d '%s'\n", pp->name,
          i + 1, pp->arg[i].type.name);
    }
  }
}

static const char *check_label_read_ref(struct parsed_op *po,
  const char *name, int *is_import)
{
  const struct parsed_proto *pp;

  pp = proto_parse(g_fhdr, name, 0);
  if (pp == NULL)
    ferr(po, "proto_parse failed for ref '%s'\n", name);

  if (pp->is_func)
    check_func_pp(po, pp, "ref");

  if (is_import != NULL)
    *is_import = pp->is_import;

  return pp->name;
}

static void check_opr(struct parsed_op *po, struct parsed_opr *popr)
{
  if (popr->segment == SEG_FS)
    ferr(po, "fs: used\n");
  if (popr->segment == SEG_GS)
    ferr(po, "gs: used\n");
}

static char *out_src_opr(char *buf, size_t buf_size,
  struct parsed_op *po, struct parsed_opr *popr, const char *cast,
  int is_lea)
{
  char tmp1[256], tmp2[256];
  char expr[256];
  const char *name;
  int is_import = 0;
  char *p;
  int ret;

  check_opr(po, popr);

  if (cast == NULL)
    cast = "";

  switch (popr->type) {
  case OPT_REG:
    if (is_lea)
      ferr(po, "lea from reg?\n");

    switch (popr->lmod) {
    case OPLM_QWORD:
      snprintf(buf, buf_size, "%s%s.q", cast, opr_reg_p(po, popr));
      break;
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
    name = check_label_read_ref(po, popr->name, &is_import);
    if (is_import)
      // for imported data, asm is loading the offset
      goto do_offset;

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
  do_offset:
    name = check_label_read_ref(po, popr->name, NULL);
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
  check_opr(po, popr);

  switch (popr->type) {
  case OPT_REG:
    switch (popr->lmod) {
    case OPLM_QWORD:
      snprintf(buf, buf_size, "%s.q", opr_reg_p(po, popr));
      break;
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

// do we need a helper func to perform a float i/o?
static int float_opr_needs_helper(struct parsed_op *po,
  struct parsed_opr *popr)
{
  if (!(g_sct_func_attr & SCTFA_UA_FLOAT))
    return 0;
  if (popr->type != OPT_REGMEM)
    return 0;
  if (is_stack_access(po, popr))
    return 0;

  return 1;
}

static char *out_opr_float(char *buf, size_t buf_size,
  struct parsed_op *po, struct parsed_opr *popr, int is_src,
  int need_float_stack)
{
  const char *cast = NULL;
  char tmp[256];
  union {
    float f;
    int i;
  } u;

  switch (popr->type) {
  case OPT_REG:
    if (popr->reg < xST0 || popr->reg > xST7) {
      // func arg
      ferr_assert(po, po->op == OP_PUSH);
      ferr_assert(po, popr->lmod == OPLM_DWORD);
      snprintf(buf, buf_size, "*(float *)&%s", opr_reg_p(po, popr));
      break;
    }

    if (need_float_stack) {
      if (popr->reg == xST0)
        snprintf(buf, buf_size, "f_st[f_stp & 7]");
      else
        snprintf(buf, buf_size, "f_st[(f_stp + %d) & 7]",
          popr->reg - xST0);
    }
    else
      snprintf(buf, buf_size, "f_st%d", popr->reg - xST0);
    break;

  case OPT_REGMEM:
    if (popr->lmod == OPLM_QWORD && is_stack_access(po, popr)) {
      stack_frame_access(po, popr, buf, buf_size,
        popr->name, "", is_src, 0);
      break;
    }
    // fallthrough
  case OPT_LABEL:
  case OPT_OFFSET:
    switch (popr->lmod) {
    case OPLM_QWORD:
      cast = "double";
      break;
    case OPLM_DWORD:
      cast = "float";
      break;
    default:
      ferr(po, "unhandled lmod: %d\n", popr->lmod);
      break;
    }
    out_src_opr(tmp, sizeof(tmp), po, popr, "", 1);
    if (is_src && float_opr_needs_helper(po, popr))
      snprintf(buf, buf_size, "%s_load(%s)", cast, tmp);
    else
      snprintf(buf, buf_size, "*(%s *)(%s)", cast, tmp);
    break;

  case OPT_CONST:
    // only for func float args pushes
    ferr_assert(po, po->op == OP_PUSH);
    u.i = po->operand[0].val;
    if (ceilf(u.f) == u.f)
      snprintf(buf, buf_size, "%.1ff", u.f);
    else
      snprintf(buf, buf_size, "%.8ff", u.f);
    break;

  default:
    ferr(po, "invalid float type: %d\n", popr->type);
  }

  return buf;
}

static char *out_src_opr_float(char *buf, size_t buf_size,
  struct parsed_op *po, struct parsed_opr *popr, int need_float_stack)
{
  return out_opr_float(buf, buf_size, po, popr, 1, need_float_stack);
}

static char *out_dst_opr_float(char *buf, size_t buf_size,
  struct parsed_op *po, struct parsed_opr *popr, int need_float_stack)
{
  return out_opr_float(buf, buf_size, po, popr, 0, need_float_stack);
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
  case PFO_BE: // CF==1||ZF==1; CF=0
    snprintf(buf, buf_size, "(%s%s %s 0)",
      cast, expr, is_inv ? "!=" : "==");
    break;

  case PFO_S:
  case PFO_L: // SF!=OF; OF=0
    snprintf(buf, buf_size, "(%s%s %s 0)",
      scast, expr, is_inv ? ">=" : "<");
    break;

  case PFO_LE: // ZF==1||SF!=OF; OF=0
    snprintf(buf, buf_size, "(%s%s %s 0)",
      scast, expr, is_inv ? ">" : "<=");
    break;

  case PFO_C: // CF=0
  case PFO_O: // OF=0
    snprintf(buf, buf_size, "(%d)", !!is_inv);
    break;

  case PFO_P: // PF==1
    snprintf(buf, buf_size, "(%sdo_parity(%s))",
      is_inv ? "!" : "", expr);
    break;

  default:
    ferr(po, "%s: unhandled parsed_flag_op: %d\n", __func__, pfo);
  }
}

static void out_cmp_for_cc(char *buf, size_t buf_size,
  struct parsed_op *po, enum parsed_flag_op pfo, int is_inv,
  int is_neg)
{
  const char *cast, *scast, *cast_use;
  char buf1[256], buf2[256];
  enum opr_lenmod lmod;

  if (po->op != OP_DEC && po->operand[0].lmod != po->operand[1].lmod)
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
  if (po->op == OP_DEC)
    snprintf(buf2, sizeof(buf2), "1");
  else {
    char cast_op2[64];
    snprintf(cast_op2, sizeof(cast_op2) - 1, "%s", cast_use);
    if (is_neg)
      strcat(cast_op2, "-");
    out_src_opr(buf2, sizeof(buf2), po, &po->operand[1], cast_op2, 0);
  }

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

  case PFO_LE: // !g
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
    out_cmp_for_cc(buf, buf_size, po, pfo, is_inv, 0);
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

// last op in stream - unconditional branch or ret
#define LAST_OP(_i) ((ops[_i].flags & OPF_TAIL) \
  || ((ops[_i].flags & (OPF_JMP|OPF_CJMP|OPF_RMD)) == OPF_JMP \
      && ops[_i].op != OP_CALL))

#define check_i(po, i) \
  if ((i) < 0) \
    ferr(po, "bad " #i ": %d\n", i)

// note: this skips over calls and rm'd stuff assuming they're handled
// so it's intended to use at one of final passes
// exception: doesn't skip OPF_RSAVE stuff
static int scan_for_pop(int i, int opcnt, int magic, int reg,
  int depth, int seen_noreturn, int save_level, int flags_set)
{
  struct parsed_op *po;
  int relevant;
  int ret = 0;
  int j;

  for (; i < opcnt; i++) {
    po = &ops[i];
    if (po->cc_scratch == magic)
      return ret; // already checked
    po->cc_scratch = magic;

    if (po->flags & OPF_TAIL) {
      if (po->op == OP_CALL && po->pp != NULL && po->pp->is_noreturn) {
        // msvc sometimes generates stack cleanup code after
        // noreturn, set a flag and continue
        seen_noreturn = 1;

        // ... but stop if there is another path to next insn -
        // if msvc skipped something stack tracking may mess up
        if (i + 1 < opcnt && g_labels[i + 1] != NULL)
          goto out;
      }
      else
        goto out;
    }

    if (po->flags & OPF_FARG)
      continue;
    if (po->flags & (OPF_RMD|OPF_DONE)) {
      if (!(po->flags & OPF_RSAVE))
        continue;
      // reprocess, there might be another push in some "parallel"
      // path that took a pop what we should also take
    }

    if ((po->flags & OPF_JMP) && po->op != OP_CALL) {
      if (po->btj != NULL) {
        // jumptable
        for (j = 0; j < po->btj->count; j++) {
          check_i(po, po->btj->d[j].bt_i);
          ret |= scan_for_pop(po->btj->d[j].bt_i, opcnt, magic, reg,
                   depth, seen_noreturn, save_level, flags_set);
          if (ret < 0)
            return ret; // dead end
        }
        return ret;
      }

      check_i(po, po->bt_i);
      if (po->flags & OPF_CJMP) {
        ret |= scan_for_pop(po->bt_i, opcnt, magic, reg,
                 depth, seen_noreturn, save_level, flags_set);
        if (ret < 0)
          return ret; // dead end
      }
      else {
        i = po->bt_i - 1;
      }
      continue;
    }

    relevant = 0;
    if ((po->op == OP_POP || po->op == OP_PUSH)
      && po->operand[0].type == OPT_REG && po->operand[0].reg == reg)
    {
      relevant = 1;
    }

    if (po->op == OP_PUSH) {
      depth++;
    }
    else if (po->op == OP_POP) {
      if (relevant && depth == 0) {
        if (flags_set == 0 && save_level > 0) {
          ret = scan_for_pop(i + 1, opcnt, magic, reg,
                  depth, seen_noreturn, save_level - 1, flags_set);
          if (ret != 1)
            // no pop for other levels, current one must be false
            return -1;
        }
        po->flags |= flags_set;
        return 1;
      }
      depth--;
    }
  }

out:
  // for noreturn, assume msvc skipped stack cleanup
  return seen_noreturn ? 1 : -1;
}

// scan for 'reg' pop backwards starting from i
// intended to use for register restore search, so other reg
// references are considered an error
static int scan_for_rsave_pop_reg(int i, int magic, int reg, int set_flags)
{
  struct parsed_op *po;
  struct label_ref *lr;
  int ret = 0;

  ops[i].cc_scratch = magic;

  while (1)
  {
    if (g_labels[i] != NULL) {
      lr = &g_label_refs[i];
      for (; lr != NULL; lr = lr->next) {
        check_i(&ops[i], lr->i);
        ret |= scan_for_rsave_pop_reg(lr->i, magic, reg, set_flags);
        if (ret < 0)
          return ret;
      }
      if (i > 0 && LAST_OP(i - 1))
        return ret;
    }

    i--;
    if (i < 0)
      break;

    if (ops[i].cc_scratch == magic)
      return ret;
    ops[i].cc_scratch = magic;

    po = &ops[i];
    if (po->op == OP_POP && po->operand[0].reg == reg) {
      if (po->flags & (OPF_RMD|OPF_DONE))
        return -1;

      po->flags |= set_flags;
      return 1;
    }

    // this also covers the case where we reach corresponding push
    if ((po->regmask_dst | po->regmask_src) & (1 << reg))
      return -1;
  }

  // nothing interesting on this path,
  // still return ret for something recursive calls could find
  return ret;
}

static void find_reachable_exits(int i, int opcnt, int magic,
  int *exits, int *exit_count)
{
  struct parsed_op *po;
  int j;

  for (; i < opcnt; i++)
  {
    po = &ops[i];
    if (po->cc_scratch == magic)
      return;
    po->cc_scratch = magic;

    if (po->flags & OPF_TAIL) {
      ferr_assert(po, *exit_count < MAX_EXITS);
      exits[*exit_count] = i;
      (*exit_count)++;
      return;
    }

    if ((po->flags & OPF_JMP) && po->op != OP_CALL) {
      if (po->flags & OPF_RMD)
        continue;

      if (po->btj != NULL) {
        for (j = 0; j < po->btj->count; j++) {
          check_i(po, po->btj->d[j].bt_i);
          find_reachable_exits(po->btj->d[j].bt_i, opcnt, magic,
                  exits, exit_count);
        }
        return;
      }

      check_i(po, po->bt_i);
      if (po->flags & OPF_CJMP)
        find_reachable_exits(po->bt_i, opcnt, magic, exits, exit_count);
      else
        i = po->bt_i - 1;
      continue;
    }
  }
}

// scan for 'reg' pop backwards starting from exits (all paths)
static int scan_for_pop_ret(int i, int opcnt, int reg, int set_flags)
{
  static int exits[MAX_EXITS];
  static int exit_count;
  int found = 0;
  int e, j, ret;

  if (!set_flags) {
    exit_count = 0;
    find_reachable_exits(i, opcnt, i + opcnt * 15, exits,
      &exit_count);
    ferr_assert(&ops[i], exit_count > 0);
  }

  for (j = 0; j < exit_count; j++) {
    e = exits[j];
    ret = scan_for_rsave_pop_reg(e, i + opcnt * 16 + set_flags,
            reg, set_flags);
    if (ret != -1) {
      found |= ret;
      continue;
    }
    if (ops[e].op == OP_CALL && ops[e].pp != NULL
      && ops[e].pp->is_noreturn)
    {
      // assume stack cleanup was skipped
      continue;
    }
    return -1;
  }

  return found;
}

// scan for one or more pop of push <const>
static int scan_for_pop_const_r(int i, int opcnt, int magic,
  int push_i, int is_probe)
{
  struct parsed_op *po;
  struct label_ref *lr;
  int ret = 0;
  int j;

  for (; i < opcnt; i++)
  {
    po = &ops[i];
    if (po->cc_scratch == magic)
      return ret; // already checked
    po->cc_scratch = magic;

    if (po->flags & OPF_JMP) {
      if (po->flags & OPF_RMD)
        continue;
      if (po->op == OP_CALL)
        return -1;

      if (po->btj != NULL) {
        for (j = 0; j < po->btj->count; j++) {
          check_i(po, po->btj->d[j].bt_i);
          ret |= scan_for_pop_const_r(po->btj->d[j].bt_i, opcnt, magic,
                  push_i, is_probe);
          if (ret < 0)
            return ret;
        }
        return ret;
      }

      check_i(po, po->bt_i);
      if (po->flags & OPF_CJMP) {
        ret |= scan_for_pop_const_r(po->bt_i, opcnt, magic, push_i,
                 is_probe);
        if (ret < 0)
          return ret;
      }
      else {
        i = po->bt_i - 1;
      }
      continue;
    }

    if ((po->flags & (OPF_TAIL|OPF_RSAVE)) || po->op == OP_PUSH)
      return -1;

    if (g_labels[i] != NULL) {
      // all refs must be visited
      lr = &g_label_refs[i];
      for (; lr != NULL; lr = lr->next) {
        check_i(po, lr->i);
        if (ops[lr->i].cc_scratch != magic)
          return -1;
      }
      if (i > 0 && !LAST_OP(i - 1) && ops[i - 1].cc_scratch != magic)
        return -1;
    }

    if (po->op == OP_POP)
    {
      if (po->flags & (OPF_RMD|OPF_DONE))
        return -1;

      if (!is_probe) {
        po->flags |= OPF_DONE;
        po->datap = &ops[push_i];
      }
      return 1;
    }
  }

  return -1;
}

static void scan_for_pop_const(int i, int opcnt, int magic)
{
  int ret;

  ret = scan_for_pop_const_r(i + 1, opcnt, magic, i, 1);
  if (ret == 1) {
    ops[i].flags |= OPF_RMD | OPF_DONE;
    scan_for_pop_const_r(i + 1, opcnt, magic + 1, i, 0);
  }
}

// check if all branch targets within a marked path are also marked
// note: the path checked must not be empty or end with a branch
static int check_path_branches(int opcnt, int magic)
{
  struct parsed_op *po;
  int i, j;

  for (i = 0; i < opcnt; i++) {
    po = &ops[i];
    if (po->cc_scratch != magic)
      continue;

    if (po->flags & OPF_JMP) {
      if ((po->flags & OPF_RMD) || po->op == OP_CALL)
        continue;

      if (po->btj != NULL) {
        for (j = 0; j < po->btj->count; j++) {
          check_i(po, po->btj->d[j].bt_i);
          if (ops[po->btj->d[j].bt_i].cc_scratch != magic)
            return 0;
        }
      }

      check_i(po, po->bt_i);
      if (ops[po->bt_i].cc_scratch != magic)
        return 0;
      if ((po->flags & OPF_CJMP) && ops[i + 1].cc_scratch != magic)
        return 0;
    }
  }

  return 1;
}

// scan for multiple pushes for given pop
static int scan_pushes_for_pop_r(int i, int magic, int pop_i,
  int is_probe)
{
  int reg = ops[pop_i].operand[0].reg;
  struct parsed_op *po;
  struct label_ref *lr;
  int ret = 0;

  ops[i].cc_scratch = magic;

  while (1)
  {
    if (g_labels[i] != NULL) {
      lr = &g_label_refs[i];
      for (; lr != NULL; lr = lr->next) {
        check_i(&ops[i], lr->i);
        ret |= scan_pushes_for_pop_r(lr->i, magic, pop_i, is_probe);
        if (ret < 0)
          return ret;
      }
      if (i > 0 && LAST_OP(i - 1))
        return ret;
    }

    i--;
    if (i < 0)
      break;

    if (ops[i].cc_scratch == magic)
      return ret;
    ops[i].cc_scratch = magic;

    po = &ops[i];
    if (po->op == OP_CALL)
      return -1;
    if ((po->flags & (OPF_TAIL|OPF_RSAVE)) || po->op == OP_POP)
      return -1;

    if (po->op == OP_PUSH)
    {
      if (po->datap != NULL)
        return -1;
      if (po->operand[0].type == OPT_REG && po->operand[0].reg == reg)
        // leave this case for reg save/restore handlers
        return -1;

      if (!is_probe) {
        po->flags |= OPF_PPUSH | OPF_DONE;
        po->datap = &ops[pop_i];
      }
      return 1;
    }
  }

  return -1;
}

static void scan_pushes_for_pop(int i, int opcnt, int *regmask_pp)
{
  int magic = i + opcnt * 14;
  int ret;

  ret = scan_pushes_for_pop_r(i, magic, i, 1);
  if (ret == 1) {
    ret = check_path_branches(opcnt, magic);
    if (ret == 1) {
      ops[i].flags |= OPF_PPUSH | OPF_DONE;
      *regmask_pp |= 1 << ops[i].operand[0].reg;
      scan_pushes_for_pop_r(i, magic + 1, i, 0);
    }
  }
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
        for (j = 0; j < po->btj->count; j++) {
          check_i(po, po->btj->d[j].bt_i);
          scan_propagate_df(po->btj->d[j].bt_i, opcnt);
        }
        return;
      }

      if (po->flags & OPF_RMD)
        continue;
      check_i(po, po->bt_i);
      if (po->flags & OPF_CJMP)
        scan_propagate_df(po->bt_i, opcnt);
      else
        i = po->bt_i - 1;
      continue;
    }

    if (po->flags & OPF_TAIL)
      break;

    if (po->op == OP_CLD) {
      po->flags |= OPF_RMD | OPF_DONE;
      return;
    }
  }

  ferr(po, "missing DF clear?\n");
}

// is operand 'opr' referenced by parsed_op 'po'?
static int is_opr_referenced(const struct parsed_opr *opr,
  const struct parsed_op *po)
{
  int i, mask;

  if (opr->type == OPT_REG) {
    mask = po->regmask_dst | po->regmask_src;
    if (po->op == OP_CALL)
      mask |= (1 << xAX) | (1 << xCX) | (1 << xDX);
    if ((1 << opr->reg) & mask)
      return 1;
    else
      return 0;
  }

  for (i = 0; i < po->operand_cnt; i++)
    if (IS(po->operand[0].name, opr->name))
      return 1;

  return 0;
}

// is operand 'opr' read by parsed_op 'po'?
static int is_opr_read(const struct parsed_opr *opr,
  const struct parsed_op *po)
{
  if (opr->type == OPT_REG) {
    if (po->regmask_src & (1 << opr->reg))
      return 1;
    else
      return 0;
  }

  // yes I'm lazy
  return 0;
}

// is operand 'opr' modified by parsed_op 'po'?
static int is_opr_modified(const struct parsed_opr *opr,
  const struct parsed_op *po)
{
  int mask;

  if (opr->type == OPT_REG) {
    if (po->op == OP_CALL) {
      mask = po->regmask_dst;
      mask |= (1 << xAX) | (1 << xCX) | (1 << xDX); // ?
      if (mask & (1 << opr->reg))
        return 1;
      else
        return 0;
    }

    if (po->regmask_dst & (1 << opr->reg))
      return 1;
    else
      return 0;
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

static int try_resolve_const(int i, const struct parsed_opr *opr,
  int magic, unsigned int *val);

static int scan_for_flag_set(int i, int opcnt, int magic,
  int *branched, int *setters, int *setter_cnt)
{
  struct label_ref *lr;
  int ret;

  while (i >= 0) {
    if (ops[i].cc_scratch == magic) {
      // is this a problem?
      //ferr(&ops[i], "%s looped\n", __func__);
      return 0;
    }
    ops[i].cc_scratch = magic;

    if (g_labels[i] != NULL) {
      *branched = 1;

      lr = &g_label_refs[i];
      for (; lr->next; lr = lr->next) {
        check_i(&ops[i], lr->i);
        ret = scan_for_flag_set(lr->i, opcnt, magic,
                branched, setters, setter_cnt);
        if (ret < 0)
          return ret;
      }

      check_i(&ops[i], lr->i);
      if (i > 0 && LAST_OP(i - 1)) {
        i = lr->i;
        continue;
      }
      ret = scan_for_flag_set(lr->i, opcnt, magic,
              branched, setters, setter_cnt);
      if (ret < 0)
        return ret;
    }
    i--;

    if (ops[i].flags & OPF_FLAGS) {
      setters[*setter_cnt] = i;
      (*setter_cnt)++;

      if (ops[i].flags & OPF_REP) {
        struct parsed_opr opr = OPR_INIT(OPT_REG, OPLM_DWORD, xCX);
        unsigned int uval;

        ret = try_resolve_const(i, &opr, i + opcnt * 7, &uval);
        if (ret != 1 || uval == 0) {
          // can't treat it as full setter because of ecx=0 case,
          // also disallow delayed compare
          *branched = 1;
          continue;
        }
      }

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
    if (g_labels[i] != NULL) {
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
    if (g_labels[i] != NULL) {
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

static void patch_esp_adjust(struct parsed_op *po, int adj)
{
  ferr_assert(po, po->op == OP_ADD);
  ferr_assert(po, IS(opr_name(po, 0), "esp"));
  ferr_assert(po, po->operand[1].type == OPT_CONST);

  // this is a bit of a hack, but deals with use of
  // single adj for multiple calls
  po->operand[1].val -= adj;
  po->flags |= OPF_RMD;
  if (po->operand[1].val == 0)
    po->flags |= OPF_DONE;
  ferr_assert(po, (int)po->operand[1].val >= 0);
}

// scan for positive, constant esp adjust
// multipath case is preliminary
static int scan_for_esp_adjust(int i, int opcnt,
  int adj_expect, int *adj, int *is_multipath, int do_update)
{
  int adj_expect_unknown = 0;
  struct parsed_op *po;
  int first_pop = -1;
  int adj_best = 0;

  *adj = *is_multipath = 0;
  if (adj_expect < 0) {
    adj_expect_unknown = 1;
    adj_expect = 32 * 4; // enough?
  }

  for (; i < opcnt && *adj < adj_expect; i++) {
    if (g_labels[i] != NULL)
      *is_multipath = 1;

    po = &ops[i];
    if (po->flags & OPF_DONE)
      continue;

    if (po->op == OP_ADD && po->operand[0].reg == xSP) {
      if (po->operand[1].type != OPT_CONST)
        ferr(&ops[i], "non-const esp adjust?\n");
      *adj += po->operand[1].val;
      if (*adj & 3)
        ferr(&ops[i], "unaligned esp adjust: %x\n", *adj);
      if (do_update) {
        if (!*is_multipath)
          patch_esp_adjust(po, adj_expect);
        else
          po->flags |= OPF_RMD;
      }
      return i;
    }
    else if (po->op == OP_PUSH) {
      //if (first_pop == -1)
      //  first_pop = -2; // none
      *adj -= lmod_bytes(po, po->operand[0].lmod);
    }
    else if (po->op == OP_POP) {
      if (!(po->flags & OPF_DONE)) {
        // seems like msvc only uses 'pop ecx' for stack realignment..
        if (po->operand[0].type != OPT_REG || po->operand[0].reg != xCX)
          break;
        if (first_pop == -1 && *adj >= 0)
          first_pop = i;
      }
      if (do_update && *adj >= 0) {
        po->flags |= OPF_RMD;
        if (!*is_multipath)
          po->flags |= OPF_DONE | OPF_NOREGS;
      }

      *adj += lmod_bytes(po, po->operand[0].lmod);
      if (*adj > adj_best)
        adj_best = *adj;
    }
    else if (po->flags & (OPF_JMP|OPF_TAIL)) {
      if (po->op == OP_JMP && po->btj == NULL) {
        if (po->bt_i <= i)
          break;
        i = po->bt_i - 1;
        continue;
      }
      if (po->op != OP_CALL)
        break;
      if (po->operand[0].type != OPT_LABEL)
        break;
      if (po->pp != NULL && po->pp->is_stdcall)
        break;
      if (adj_expect_unknown && first_pop >= 0)
        break;
      // assume it's another cdecl call
    }
  }

  if (first_pop >= 0) {
    // probably only 'pop ecx' was used
    *adj = adj_best;
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
  struct parsed_op *po, const struct parsed_opr *opr,
  int is_call, int *search_instead)
{
  const struct parsed_proto *pp = NULL;
  char buf[256];
  char *p;

  if (po->pp != NULL && (po->flags & OPF_DATA)) {
    // hint given in asm
    return po->pp;
  }

  // maybe an arg of g_func?
  if (opr->type == OPT_REGMEM && is_stack_access(po, opr))
  {
    char ofs_reg[16] = { 0, };
    int arg, arg_s, arg_i;
    int stack_ra = 0;
    int offset = 0;

    if (g_header_mode)
      return NULL;

    parse_stack_access(po, opr->name, ofs_reg,
      &offset, &stack_ra, NULL, 0);
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

    pp = g_func_pp->arg[arg].pp;
    if (is_call) {
      if (pp == NULL)
        ferr(po, "icall arg: arg%d has no pp\n", arg + 1);
      check_func_pp(po, pp, "icall arg");
    }
  }
  else if (opr->type == OPT_REGMEM && strchr(opr->name + 1, '[')) {
    // label[index]
    p = strchr(opr->name + 1, '[');
    memcpy(buf, opr->name, p - opr->name);
    buf[p - opr->name] = 0;
    pp = proto_parse(g_fhdr, buf, g_quiet_pp);
  }
  else if (opr->type == OPT_OFFSET || opr->type == OPT_LABEL) {
    pp = proto_parse(g_fhdr, opr->name, g_quiet_pp);
    if (pp == NULL) {
      if (!g_header_mode)
        ferr(po, "proto_parse failed for icall to '%s'\n", opr->name);
    }
    else
      check_func_pp(po, pp, "reg-fptr ref");
  }

  return pp;
}

static void scan_for_call_type(int i, const struct parsed_opr *opr,
  int magic, int is_call_op, const struct parsed_proto **pp_found,
  int *pp_i, int *multi)
{
  const struct parsed_proto *pp = NULL;
  struct parsed_op *po;
  struct label_ref *lr;

  ops[i].cc_scratch = magic;

  while (1) {
    if (g_labels[i] != NULL) {
      lr = &g_label_refs[i];
      for (; lr != NULL; lr = lr->next) {
        check_i(&ops[i], lr->i);
        scan_for_call_type(lr->i, opr, magic, is_call_op,
          pp_found, pp_i, multi);
      }
      if (i > 0 && LAST_OP(i - 1))
        return;
    }

    i--;
    if (i < 0)
      break;

    if (ops[i].cc_scratch == magic)
      return;
    ops[i].cc_scratch = magic;

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
    if (opr->type != OPT_REG || g_func_pp == NULL)
      return;

    for (i = 0; i < g_func_pp->argc; i++) {
      if (g_func_pp->arg[i].reg == NULL)
        continue;
      if (IS(opr->name, g_func_pp->arg[i].reg))
        break;
    }
    if (i == g_func_pp->argc)
      return;
    pp = g_func_pp->arg[i].pp;
    if (pp == NULL) {
      if (is_call_op)
        ferr(po, "icall: arg%d (%s) is not a fptr?\n",
          i + 1, g_func_pp->arg[i].reg);
      return;
    }
    check_func_pp(po, pp, "icall reg-arg");
  }
  else
    pp = try_recover_pp(po, opr, is_call_op, NULL);

  if (*pp_found != NULL && pp != NULL && *pp_found != pp) {
    if (pp_cmp_func(*pp_found, pp)) {
      if (pp_i != NULL && *pp_i != -1)
        fnote(&ops[*pp_i], "(other ref)\n");
      ferr(po, "icall: parsed_proto mismatch\n");
    }
    if (multi != NULL)
      *multi = 1;
  }
  if (pp != NULL) {
    *pp_found = pp;
    if (pp_i != NULL)
      *pp_i = po - ops;
  }
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

static struct parsed_data *try_resolve_jumptab(int i, int opcnt)
{
  struct parsed_op *po = &ops[i];
  struct parsed_data *pd;
  char label[NAMELEN], *p;
  int len, j, l;

  p = strchr(po->operand[0].name, '[');
  if (p == NULL)
    return NULL;

  len = p - po->operand[0].name;
  strncpy(label, po->operand[0].name, len);
  label[len] = 0;

  for (j = 0, pd = NULL; j < g_func_pd_cnt; j++) {
    if (IS(g_func_pd[j].label, label)) {
      pd = &g_func_pd[j];
      break;
    }
  }
  if (pd == NULL)
    //ferr(po, "label '%s' not parsed?\n", label);
    return NULL;

  if (pd->type != OPT_OFFSET)
    ferr(po, "label '%s' with non-offset data?\n", label);

  // find all labels, link
  for (j = 0; j < pd->count; j++) {
    for (l = 0; l < opcnt; l++) {
      if (g_labels[l] != NULL && IS(g_labels[l], pd->d[j].u.label)) {
        add_label_ref(&g_label_refs[l], i);
        pd->d[j].bt_i = l;
        break;
      }
    }
  }

  return pd;
}

static void clear_labels(int count)
{
  int i;

  for (i = 0; i < count; i++) {
    if (g_labels[i] != NULL) {
      free(g_labels[i]);
      g_labels[i] = NULL;
    }
  }
}

static int get_pp_arg_regmask_src(const struct parsed_proto *pp)
{
  int regmask = 0;
  int i, reg;

  for (i = 0; i < pp->argc; i++) {
    if (pp->arg[i].reg != NULL) {
      reg = char_array_i(regs_r32,
              ARRAY_SIZE(regs_r32), pp->arg[i].reg);
      if (reg < 0)
        ferr(ops, "arg '%s' of func '%s' is not a reg?\n",
          pp->arg[i].reg, pp->name);
      regmask |= 1 << reg;
    }
  }

  return regmask;
}

static int get_pp_arg_regmask_dst(const struct parsed_proto *pp)
{
  int regmask = 0;
  int i, reg;

  if (pp->has_retreg) {
    for (i = 0; i < pp->argc; i++) {
      if (pp->arg[i].type.is_retreg) {
        reg = char_array_i(regs_r32,
                ARRAY_SIZE(regs_r32), pp->arg[i].reg);
        ferr_assert(ops, reg >= 0);
        regmask |= 1 << reg;
      }
    }
  }

  if (strstr(pp->ret_type.name, "int64"))
    return regmask | (1 << xAX) | (1 << xDX);
  if (IS(pp->ret_type.name, "float")
   || IS(pp->ret_type.name, "double"))
  {
    return regmask | mxST0;
  }
  if (strcasecmp(pp->ret_type.name, "void") == 0)
    return regmask;

  return regmask | mxAX;
}

static int are_ops_same(struct parsed_op *po1, struct parsed_op *po2)
{
  return po1->op == po2->op && po1->operand_cnt == po2->operand_cnt
    && memcmp(po1->operand, po2->operand,
              sizeof(po1->operand[0]) * po1->operand_cnt) == 0;
}

static void resolve_branches_parse_calls(int opcnt)
{
  static const struct {
    const char *name;
    enum op_op op;
    unsigned int flags;
    unsigned int regmask_src;
    unsigned int regmask_dst;
  } pseudo_ops[] = {
    { "__allshl", OPP_ALLSHL, OPF_DATA, mxAX|mxDX|mxCX, mxAX|mxDX },
    { "__allshr", OPP_ALLSHR, OPF_DATA, mxAX|mxDX|mxCX, mxAX|mxDX },
    { "__ftol",   OPP_FTOL,   OPF_FPOP, mxST0, mxAX | mxDX },
    // more precise? Wine gets away with just __ftol handler
    { "__ftol2",  OPP_FTOL,   OPF_FPOP, mxST0, mxAX | mxDX },
    { "__CIpow",  OPP_CIPOW,  OPF_FPOP, mxST0|mxST1, mxST0 },
  };
  const struct parsed_proto *pp_c;
  struct parsed_proto *pp;
  struct parsed_data *pd;
  struct parsed_op *po;
  const char *tmpname;
  enum op_op prev_op;
  int i, l;
  int ret;

  for (i = 0; i < opcnt; i++)
  {
    po = &ops[i];
    po->bt_i = -1;
    po->btj = NULL;

    if (po->datap != NULL) {
      pp = calloc(1, sizeof(*pp));
      my_assert_not(pp, NULL);

      ret = parse_protostr(po->datap, pp);
      if (ret < 0)
        ferr(po, "bad protostr supplied: %s\n", (char *)po->datap);
      free(po->datap);
      po->datap = NULL;
      po->pp = pp;
    }

    if (po->op == OP_CALL) {
      pp = NULL;

      if (po->pp != NULL)
        pp = po->pp;
      else if (po->operand[0].type == OPT_LABEL)
      {
        tmpname = opr_name(po, 0);
        if (IS_START(tmpname, "loc_")) {
          if (!g_seh_found)
            ferr(po, "call to loc_*\n");
          // eliminate_seh() must take care of it
          continue;
        }
        if (IS(tmpname, "__alloca_probe"))
          continue;
        if (IS(tmpname, "__SEH_prolog")) {
          ferr_assert(po, g_seh_found == 0);
          g_seh_found = 2;
          continue;
        }
        if (IS(tmpname, "__SEH_epilog"))
          continue;

        // convert some calls to pseudo-ops
        for (l = 0; l < ARRAY_SIZE(pseudo_ops); l++) {
          if (!IS(tmpname, pseudo_ops[l].name))
            continue;

          po->op = pseudo_ops[l].op;
          po->operand_cnt = 0;
          po->regmask_src = pseudo_ops[l].regmask_src;
          po->regmask_dst = pseudo_ops[l].regmask_dst;
          po->flags &= OPF_TAIL;
          po->flags |= pseudo_ops[l].flags;
          po->flags |= po->regmask_dst ? OPF_DATA : 0;
          break;
        }
        if (l < ARRAY_SIZE(pseudo_ops))
          continue;

        pp_c = proto_parse(g_fhdr, tmpname, g_header_mode);
        if (!g_header_mode && pp_c == NULL)
          ferr(po, "proto_parse failed for call '%s'\n", tmpname);

        if (pp_c != NULL) {
          pp = proto_clone(pp_c);
          my_assert_not(pp, NULL);
        }
      }

      if (pp != NULL) {
        if (pp->is_fptr)
          check_func_pp(po, pp, "fptr var call");
        if (pp->is_noreturn) {
          po->flags |= OPF_TAIL;
          po->flags &= ~OPF_ATAIL; // most likely...
        }
      }
      po->pp = pp;
      continue;
    }

    if (!(po->flags & OPF_JMP) || po->op == OP_RET)
      continue;

    if (po->operand[0].type == OPT_REGMEM) {
      pd = try_resolve_jumptab(i, opcnt);
      if (pd == NULL)
        goto tailcall;

      po->btj = pd;
      continue;
    }

    for (l = 0; l < opcnt; l++) {
      if (g_labels[l] != NULL
          && IS(po->operand[0].name, g_labels[l]))
      {
        if (l == i + 1 && po->op == OP_JMP) {
          // yet another alignment type...
          po->flags |= OPF_RMD | OPF_DONE;
          po->flags &= ~OPF_JMP;
          po->op = OP_NOP;
          break;
        }
        add_label_ref(&g_label_refs[l], i);
        po->bt_i = l;
        break;
      }
    }

    if (po->bt_i != -1 || (po->flags & OPF_RMD))
      continue;

    if (po->operand[0].type == OPT_LABEL
        || po->operand[0].type == OPT_REG)
      // assume tail call
      goto tailcall;

    ferr(po, "unhandled branch\n");

tailcall:
    po->op = OP_CALL;
    po->flags |= OPF_TAIL;
    prev_op = i > 0 ? ops[i - 1].op : OP_UD2;
    if (prev_op == OP_POP)
      po->flags |= OPF_ATAIL;
    if (g_stack_fsz + g_bp_frame == 0 && prev_op != OP_PUSH
      && (g_func_pp == NULL || g_func_pp->argc_stack > 0))
    {
      po->flags |= OPF_ATAIL;
    }
    i--; // reprocess
  }
}

static int resolve_origin(int i, const struct parsed_opr *opr,
  int magic, int *op_i, int *is_caller);
static void set_label(int i, const char *name);

static void eliminate_seh_writes(int opcnt)
{
  const struct parsed_opr *opr;
  char ofs_reg[16];
  int offset;
  int i;

  // assume all sf writes above g_seh_size to be seh related
  // (probably unsafe but oh well)
  for (i = 0; i < opcnt; i++) {
    if (ops[i].op != OP_MOV)
      continue;
    opr = &ops[i].operand[0];
    if (opr->type != OPT_REGMEM)
      continue;
    if (!is_stack_access(&ops[i], opr))
      continue;

    offset = 0;
    parse_stack_access(&ops[i], opr->name, ofs_reg, &offset,
      NULL, NULL, 0);
    if (offset < 0 && offset >= -g_seh_size)
      ops[i].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
  }
}

static void eliminate_seh_finally(int opcnt)
{
  const char *target_name = NULL;
  const char *return_name = NULL;
  int exits[MAX_EXITS];
  int exit_count = 0;
  int call_i = -1;
  int target_i = -1;
  int return_i = -1;
  int tgend_i = -1;
  int i;

  for (i = 0; i < opcnt; i++) {
    if (ops[i].op != OP_CALL)
      continue;
    if (!IS_START(opr_name(&ops[i], 0), "loc_"))
      continue;
    if (target_name != NULL)
      ferr(&ops[i], "multiple finally calls? (last was %s)\n",
        target_name);
    target_name = opr_name(&ops[i], 0);
    call_i = i;

    if (g_labels[i + 1] == NULL)
      set_label(i + 1, "seh_fin_done");
    return_name = g_labels[i + 1];
    return_i = i + 1;
  }

  if (call_i == -1)
    // no finally block
    return;

  // find finally code (bt_i is not set because it's call)
  for (i = 0; i < opcnt; i++) {
    if (g_labels[i] == NULL)
      continue;
    if (!IS(g_labels[i], target_name))
      continue;

    ferr_assert(&ops[i], target_i == -1);
    target_i = i;
  }
  ferr_assert(&ops[0], target_i != -1);

  find_reachable_exits(target_i, opcnt, target_i + opcnt * 24,
    exits, &exit_count);
  ferr_assert(&ops[target_i], exit_count == 1);
  ferr_assert(&ops[target_i], ops[exits[0]].op == OP_RET);
  tgend_i = exits[0];

  // convert to jumps, link
  ops[call_i].op = OP_JMP;
  ops[call_i].bt_i = target_i;
  add_label_ref(&g_label_refs[target_i], call_i);

  ops[tgend_i].op = OP_JMP;
  ops[tgend_i].flags &= ~OPF_TAIL;
  ops[tgend_i].flags |= OPF_JMP;
  ops[tgend_i].bt_i = return_i;
  ops[tgend_i].operand_cnt = 1;
  ops[tgend_i].operand[0].type = OPT_LABEL;
  snprintf(ops[tgend_i].operand[0].name, NAMELEN, "%s", return_name);
  add_label_ref(&g_label_refs[return_i], tgend_i);

  // rm seh finally entry code
  for (i = target_i - 1; i >= 0; i--) {
    if (g_labels[i] != NULL && g_label_refs[i].i != -1)
      return;
    if (ops[i].flags & OPF_CJMP)
      return;
    if (ops[i].flags & (OPF_JMP | OPF_TAIL))
      break;
  }
  for (i = target_i - 1; i >= 0; i--) {
    if (ops[i].flags & (OPF_JMP | OPF_TAIL))
      break;
    ops[i].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
  }
}

static void eliminate_seh(int opcnt)
{
  int i, j, k, ret;

  for (i = 0; i < opcnt; i++) {
    if (ops[i].op != OP_MOV)
      continue;
    if (ops[i].operand[0].segment != SEG_FS)
      continue;
    if (!IS(opr_name(&ops[i], 0), "0"))
      continue;

    ops[i].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
    if (ops[i].operand[1].reg == xSP) {
      for (j = i - 1; j >= 0; j--) {
        if (ops[j].op != OP_PUSH)
          continue;
        ops[j].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
        g_seh_size += 4;
        if (ops[j].operand[0].val == ~0)
          break;
        if (ops[j].operand[0].type == OPT_REG) {
          k = -1;
          ret = resolve_origin(j, &ops[j].operand[0],
                  j + opcnt * 22, &k, NULL);
          if (ret == 1)
            ops[k].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
        }
      }
      if (j < 0)
        ferr(ops, "missing seh terminator\n");
    }
    else {
      k = -1;
      ret = resolve_origin(i, &ops[i].operand[1],
              i + opcnt * 23, &k, NULL);
      if (ret == 1)
        ops[k].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
    }
  }

  eliminate_seh_writes(opcnt);
  eliminate_seh_finally(opcnt);
}

static void eliminate_seh_calls(int opcnt)
{
  int epilog_found = 0;
  int i;

  g_bp_frame = 1;
  g_seh_size = 0x10;

  i = 0;
  ferr_assert(&ops[i], ops[i].op == OP_PUSH
               && ops[i].operand[0].type == OPT_CONST);
  g_stack_fsz = g_seh_size + ops[i].operand[0].val;
  ops[i].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;

  i++;
  ferr_assert(&ops[i], ops[i].op == OP_PUSH
               && ops[i].operand[0].type == OPT_OFFSET);
  ops[i].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;

  i++;
  ferr_assert(&ops[i], ops[i].op == OP_CALL
               && IS(opr_name(&ops[i], 0), "__SEH_prolog"));
  ops[i].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;

  for (i++; i < opcnt; i++) {
    if (ops[i].op != OP_CALL)
      continue;
    if (!IS(opr_name(&ops[i], 0), "__SEH_epilog"))
      continue;

    ops[i].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
    epilog_found = 1;
  }
  ferr_assert(ops, epilog_found);

  eliminate_seh_writes(opcnt);
  eliminate_seh_finally(opcnt);
}

// check for prologue of many pushes and epilogue with pops
static void check_simple_sequence(int opcnt, int *fsz)
{
  int found = 0;
  int seq_len;
  int seq_p;
  int seq[4];
  int reg;
  int i, j;

  for (i = 0; i < opcnt && i < ARRAY_SIZE(seq); i++) {
    if (ops[i].op != OP_PUSH || ops[i].operand[0].type != OPT_REG)
      break;
    reg = ops[i].operand[0].reg;
    if (reg != xBX && reg != xSI && reg != xDI && reg != xBP)
      break;
    for (j = 0; j < i; j++)
      if (seq[j] == reg)
        break;
    if (j != i)
      // probably something else is going on here
      break;
    seq[i] = reg;
  }
  seq_len = i;
  if (seq_len == 0)
    return;

  for (; i < opcnt && seq_len > 0; i++) {
    if (!(ops[i].flags & OPF_TAIL))
      continue;

    for (j = i - 1, seq_p = 0; j >= 0 && seq_p < seq_len; j--) {
      if (ops[j].op != OP_POP || ops[j].operand[0].type != OPT_REG)
        break;
      if (ops[j].operand[0].reg != seq[seq_p])
        break;
      seq_p++;
    }
    found = seq_len = seq_p;
  }
  if (!found)
    return;

  for (i = 0; i < seq_len; i++)
    ops[i].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;

  for (; i < opcnt && seq_len > 0; i++) {
    if (!(ops[i].flags & OPF_TAIL))
      continue;

    for (j = i - 1, seq_p = 0; j >= 0 && seq_p < seq_len; j--) {
      ops[j].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
      seq_p++;
    }
  }

  // unlike pushes after sub esp,
  // IDA treats pushes like this as part of var area
  *fsz += seq_len * 4;
}

static int scan_prologue_ecx(int i, int opcnt, int flags_set,
  int limit, int *ecx_push_out)
{
  const struct parsed_proto *pp;
  int ecx_push = 0, other_push = 0;
  int ret;

  while (limit > 0 && ops[i].op == OP_PUSH
         && IS(opr_name(&ops[i], 0), "ecx"))
  {
    ops[i].flags |= flags_set;
    ecx_push++;
    i++;
    limit--;
  }

  ret = i;
  if (ecx_push == 0 || flags_set != 0)
    goto out;

  // check if some of the pushes aren't really call args
  for (; i < opcnt; i++) {
    if (i > 0 && g_labels[i] != NULL)
      break;
    if (ops[i].flags & (OPF_JMP|OPF_TAIL))
      break;
    if (ops[i].op == OP_PUSH)
      other_push++;
  }

  if (ops[i].op != OP_CALL)
    goto out;

  pp = ops[i].pp;
  if (pp == NULL && ops[i].operand[0].type == OPT_LABEL)
    pp = proto_parse(g_fhdr, opr_name(&ops[i], 0), 1);
  if (pp == NULL)
    goto out;

  ferr_assert(&ops[i], ecx_push + other_push >= pp->argc_stack);
  if (other_push < pp->argc_stack)
    ecx_push -= pp->argc_stack - other_push;

out:
  if (ecx_push_out != NULL)
    *ecx_push_out = ecx_push;
  return ret;
}

static int scan_prologue(int i, int opcnt, int *ecx_push, int *esp_sub)
{
  const char *name;
  int j, len, ret;
  int ecx_tmp = 0;

  for (; i < opcnt; i++)
    if (!(ops[i].flags & OPF_DONE))
      break;

  ret = scan_prologue_ecx(i, opcnt, 0, 4, &ecx_tmp);
  if (ecx_tmp > 0) {
    scan_prologue_ecx(i, opcnt, OPF_RMD | OPF_DONE | OPF_NOREGS,
      ecx_tmp, NULL);
    g_stack_fsz += 4 * ecx_tmp;
    *ecx_push += ecx_tmp;
    i = ret;
  }

  for (; i < opcnt; i++) {
    if (i > 0 && g_labels[i] != NULL)
      break;
    if (ops[i].flags & (OPF_JMP|OPF_TAIL))
      break;
    if (ops[i].flags & OPF_DONE)
      continue;
    if (ops[i].op == OP_PUSH)
      break;
    if (ops[i].op == OP_SUB && ops[i].operand[0].reg == xSP
      && ops[i].operand[1].type == OPT_CONST)
    {
      g_stack_fsz += opr_const(&ops[i], 1);
      ops[i].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
      i++;
      *esp_sub = 1;
      break;
    }
    if (ops[i].op == OP_LEA && ops[i].operand[0].reg == xSP
      && ops[i].operand[1].type == OPT_REGMEM
      && IS_START(ops[i].operand[1].name, "esp-"))
    {
      name = ops[i].operand[1].name;
      ret = sscanf(name, "esp-%x%n", &j, &len);
      ferr_assert(&ops[i], ret == 1 && len == strlen(name));
      g_stack_fsz += j;
      ops[i].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
      i++;
      *esp_sub = 1;
      break;
    }
    if (ops[i].op == OP_MOV && ops[i].operand[0].reg == xAX
        && ops[i].operand[1].type == OPT_CONST)
    {
      for (j = i + 1; j < opcnt; j++)
        if (!(ops[j].flags & OPF_DONE))
          break;
      if (ops[j].op == OP_CALL
        && IS(opr_name(&ops[j], 0), "__alloca_probe"))
      {
        g_stack_fsz += opr_const(&ops[i], 1);
        ops[i].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
        ops[j].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
        i = j + 1;
        *esp_sub = 1;
        break;
      }
    }
  }

  return i;
}

static void scan_prologue_epilogue(int opcnt, int *stack_align)
{
  int ecx_push = 0, esp_sub = 0, pusha = 0;
  int sandard_epilogue;
  int found, ret, len;
  int push_fsz = 0;
  int i, j, l;

  if (g_seh_found == 2) {
    eliminate_seh_calls(opcnt);
    return;
  }
  if (g_seh_found) {
    eliminate_seh(opcnt);
    // ida treats seh as part of sf
    g_stack_fsz = g_seh_size;
    esp_sub = 1;
  }

  if (ops[0].op == OP_PUSH && IS(opr_name(&ops[0], 0), "ebp")
      && ops[1].op == OP_MOV
      && IS(opr_name(&ops[1], 0), "ebp")
      && IS(opr_name(&ops[1], 1), "esp"))
  {
    g_bp_frame = 1;
    ops[0].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
    ops[1].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;

    for (i = 2; i < opcnt; i++)
      if (!(ops[i].flags & OPF_DONE))
        break;

    if (ops[i].op == OP_PUSHA) {
      ops[i].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
      pusha = 1;
      i++;
    }

    if (ops[i].op == OP_AND && ops[i].operand[0].reg == xSP
        && ops[i].operand[1].type == OPT_CONST)
    {
      l = ops[i].operand[1].val;
      j = ffs(l) - 1;
      if (j == -1 || (l >> j) != -1)
        ferr(&ops[i], "unhandled esp align: %x\n", l);
      if (stack_align != NULL)
        *stack_align = 1 << j;
      ops[i].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
      i++;
    }

    i = scan_prologue(i, opcnt, &ecx_push, &esp_sub);

    found = 0;
    do {
      for (; i < opcnt; i++)
        if (ops[i].flags & OPF_TAIL)
          break;
      j = i - 1;
      if (i == opcnt && (ops[j].flags & OPF_JMP)) {
        if (ops[j].bt_i != -1 || ops[j].btj != NULL)
          break;
        i--;
        j--;
      }

      sandard_epilogue = 0;
      if (ops[j].op == OP_POP && IS(opr_name(&ops[j], 0), "ebp"))
      {
        ops[j].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
        // the standard epilogue is sometimes even used without a sf
        if (ops[j - 1].op == OP_MOV
            && IS(opr_name(&ops[j - 1], 0), "esp")
            && IS(opr_name(&ops[j - 1], 1), "ebp"))
          sandard_epilogue = 1;
      }
      else if (ops[j].op == OP_LEAVE)
      {
        ops[j].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
        sandard_epilogue = 1;
      }
      else if (ops[i].op == OP_CALL && ops[i].pp != NULL
        && ops[i].pp->is_noreturn)
      {
        // on noreturn, msvc sometimes cleans stack, sometimes not
        i++;
        found = 1;
        continue;
      }
      else if (!(g_ida_func_attr & IDAFA_NORETURN))
        ferr(&ops[j], "'pop ebp' expected\n");

      if (g_stack_fsz != 0 || sandard_epilogue) {
        if (ops[j].op == OP_LEAVE)
          j--;
        else if (sandard_epilogue) // mov esp, ebp
        {
          ops[j - 1].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
          j -= 2;
        }
        else if (!(g_ida_func_attr & IDAFA_NORETURN))
        {
          ferr(&ops[j], "esp restore expected\n");
        }

        if (ecx_push && j >= 0 && ops[j].op == OP_POP
          && IS(opr_name(&ops[j], 0), "ecx"))
        {
          ferr(&ops[j], "unexpected ecx pop\n");
        }
      }

      if (pusha) {
        if (ops[j].op == OP_POPA)
          ops[j].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
        else
          ferr(&ops[j], "popa expected\n");
      }

      found = 1;
      i++;
    } while (i < opcnt);

    if (!found)
      ferr(ops, "missing ebp epilogue\n");
    return;
  }

  // non-bp frame
  check_simple_sequence(opcnt, &push_fsz);
  i = scan_prologue(0, opcnt, &ecx_push, &esp_sub);

  found = 0;
  if (ecx_push || esp_sub)
  {
    g_sp_frame = 1;

    do {
      for (; i < opcnt; i++)
        if (ops[i].flags & OPF_TAIL)
          break;

      j = i - 1;
      if (i == opcnt && (ops[j].flags & OPF_JMP)) {
        if (ops[j].bt_i != -1 || ops[j].btj != NULL)
          break;
        i--;
        j--;
      }
      else if (i < opcnt && (ops[i].flags & OPF_ATAIL)) {
        // skip arg updates for arg-reuse tailcall
        for (; j >= 0; j--) {
          if (ops[j].op != OP_MOV)
            break;
          if (ops[j].operand[0].type == OPT_REGMEM
              && strstr(ops[j].operand[0].name, "arg_") != NULL)
            continue;
          if (ops[j].operand[0].type == OPT_REG)
            continue; // assume arg-reg mov
          break;
        }
      }

      for (; j >= 0; j--) {
        if ((ops[j].flags & (OPF_RMD | OPF_DONE | OPF_NOREGS)) !=
            (OPF_RMD | OPF_DONE | OPF_NOREGS))
          break;
      }

      if (ecx_push > 0 && !esp_sub) {
        for (l = 0; l < ecx_push && j >= 0; l++) {
          if (ops[j].op == OP_POP && IS(opr_name(&ops[j], 0), "ecx"))
            /* pop ecx */;
          else if (ops[j].op == OP_ADD
                   && IS(opr_name(&ops[j], 0), "esp")
                   && ops[j].operand[1].type == OPT_CONST)
          {
            /* add esp, N */
            l += ops[j].operand[1].val / 4 - 1;
          }
          else
            break;

          ops[j].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
          j--;
        }
        if (l != ecx_push) {
          if (i < opcnt && ops[i].op == OP_CALL
            && ops[i].pp != NULL && ops[i].pp->is_noreturn)
          {
            // noreturn tailcall with no epilogue
            i++;
            found = 1;
            continue;
          }
          ferr(&ops[j], "epilogue scan failed\n");
        }

        found = 1;
      }

      if (esp_sub) {
        if (ops[j].op == OP_ADD
            && IS(opr_name(&ops[j], 0), "esp")
            && ops[j].operand[1].type == OPT_CONST)
        {
          if (ops[j].operand[1].val < g_stack_fsz)
            ferr(&ops[j], "esp adj is too low (need %d)\n", g_stack_fsz);

          ops[j].operand[1].val -= g_stack_fsz; // for stack arg scanner
          if (ops[j].operand[1].val == 0)
            ops[j].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
          found = 1;
        }
        else if (ops[j].op == OP_LEA && ops[j].operand[0].reg == xSP
          && ops[j].operand[1].type == OPT_REGMEM
          && IS_START(ops[j].operand[1].name, "esp+"))
        {
          const char *name = ops[j].operand[1].name;
          ret = sscanf(name, "esp+%x%n", &l, &len);
          ferr_assert(&ops[j], ret == 1 && len == strlen(name));
          ferr_assert(&ops[j], l <= g_stack_fsz);
          ops[j].flags |= OPF_RMD | OPF_DONE | OPF_NOREGS;
          found = 1;
        }
        else if (i < opcnt && ops[i].op == OP_CALL
          && ops[i].pp != NULL && ops[i].pp->is_noreturn)
        {
          // noreturn tailcall with no epilogue
          found = 1;
        }
        else
          ferr(&ops[j], "'add esp' expected\n");
      }

      i++;
    } while (i < opcnt);

    if (!found)
      ferr(ops, "missing esp epilogue\n");
  }

  if (g_stack_fsz != 0)
    // see check_simple_sequence
    g_stack_fsz += push_fsz;
}

// find an instruction that changed opr before i op
// *op_i must be set to -1 by the caller
// *is_caller is set to 1 if one source is determined to be g_func arg
// returns 1 if found, *op_i is then set to origin
// returns -1 if multiple origins are found
static int resolve_origin(int i, const struct parsed_opr *opr,
  int magic, int *op_i, int *is_caller)
{
  struct label_ref *lr;
  int ret = 0;

  while (1) {
    if (g_labels[i] != NULL) {
      lr = &g_label_refs[i];
      for (; lr != NULL; lr = lr->next) {
        check_i(&ops[i], lr->i);
        ret |= resolve_origin(lr->i, opr, magic, op_i, is_caller);
      }
      if (i > 0 && LAST_OP(i - 1))
        return ret;
    }

    i--;
    if (i < 0) {
      if (is_caller != NULL)
        *is_caller = 1;
      return -1;
    }

    if (ops[i].cc_scratch == magic)
      return ret;
    ops[i].cc_scratch = magic;

    if (!(ops[i].flags & OPF_DATA))
      continue;
    if (!is_opr_modified(opr, &ops[i]))
      continue;

    if (*op_i >= 0) {
      if (*op_i == i || are_ops_same(&ops[*op_i], &ops[i]))
        return ret | 1;

      return -1;
    }

    *op_i = i;
    return ret | 1;
  }
}

static int resolve_origin_reg(int i, int reg, int magic, int *op_i,
  int *is_caller)
{
  struct parsed_opr opr = OPR_INIT(OPT_REG, OPLM_DWORD, reg);

  *op_i = -1;
  if (is_caller != NULL)
    *is_caller = 0;
  return resolve_origin(i, &opr, magic, op_i, is_caller);
}

// find an instruction that previously referenced opr
// if multiple results are found - fail
// *op_i must be set to -1 by the caller
// returns 1 if found, *op_i is then set to referencer insn
static int resolve_last_ref(int i, const struct parsed_opr *opr,
  int magic, int *op_i)
{
  struct label_ref *lr;
  int ret = 0;

  while (1) {
    if (g_labels[i] != NULL) {
      lr = &g_label_refs[i];
      for (; lr != NULL; lr = lr->next) {
        check_i(&ops[i], lr->i);
        ret |= resolve_last_ref(lr->i, opr, magic, op_i);
      }
      if (i > 0 && LAST_OP(i - 1))
        return ret;
    }

    i--;
    if (i < 0)
      return -1;

    if (ops[i].cc_scratch == magic)
      return 0;
    ops[i].cc_scratch = magic;

    if (!is_opr_referenced(opr, &ops[i]))
      continue;

    if (*op_i >= 0)
      return -1;

    *op_i = i;
    return 1;
  }
}

// adjust datap of all reachable 'op' insns when moving back
// returns  1 if at least 1 op was found
// returns -1 if path without an op was found
static int adjust_prev_op(int i, enum op_op op, int magic, void *datap)
{
  struct label_ref *lr;
  int ret = 0;

  if (ops[i].cc_scratch == magic)
    return 0;
  ops[i].cc_scratch = magic;

  while (1) {
    if (g_labels[i] != NULL) {
      lr = &g_label_refs[i];
      for (; lr != NULL; lr = lr->next) {
        check_i(&ops[i], lr->i);
        ret |= adjust_prev_op(lr->i, op, magic, datap);
      }
      if (i > 0 && LAST_OP(i - 1))
        return ret;
    }

    i--;
    if (i < 0)
      return -1;

    if (ops[i].cc_scratch == magic)
      return 0;
    ops[i].cc_scratch = magic;

    if (ops[i].op != op)
      continue;

    ops[i].datap = datap;
    return 1;
  }
}

// find next instruction that reads opr
// *op_i must be set to -1 by the caller
// on return, *op_i is set to first referencer insn
// returns 1 if exactly 1 referencer is found
static int find_next_read(int i, int opcnt,
  const struct parsed_opr *opr, int magic, int *op_i)
{
  struct parsed_op *po;
  int j, ret = 0;

  for (; i < opcnt; i++)
  {
    if (ops[i].cc_scratch == magic)
      return ret;
    ops[i].cc_scratch = magic;

    po = &ops[i];
    if ((po->flags & OPF_JMP) && po->op != OP_CALL) {
      if (po->btj != NULL) {
        // jumptable
        for (j = 0; j < po->btj->count; j++) {
          check_i(po, po->btj->d[j].bt_i);
          ret |= find_next_read(po->btj->d[j].bt_i, opcnt, opr,
                   magic, op_i);
        }
        return ret;
      }

      if (po->flags & OPF_RMD)
        continue;
      check_i(po, po->bt_i);
      if (po->flags & OPF_CJMP) {
        ret |= find_next_read(po->bt_i, opcnt, opr, magic, op_i);
        if (ret < 0)
          return ret;
      }
      else
        i = po->bt_i - 1;
      continue;
    }

    if (!is_opr_read(opr, po)) {
      int full_opr = 1;
      if (opr->type == OPT_REG && po->operand[0].type == OPT_REG
          && opr->reg == po->operand[0].reg && (po->flags & OPF_DATA))
      {
        full_opr = po->operand[0].lmod >= opr->lmod;
      }
      if (is_opr_modified(opr, po) && full_opr) {
        // it's overwritten
        return ret;
      }
      if (po->flags & OPF_TAIL)
        return ret;
      continue;
    }

    if (*op_i >= 0)
      return -1;

    *op_i = i;
    return 1;
  }

  return 0;
}

static int find_next_read_reg(int i, int opcnt, int reg,
  enum opr_lenmod lmod, int magic, int *op_i)
{
  struct parsed_opr opr = OPR_INIT(OPT_REG, lmod, reg);

  *op_i = -1;
  return find_next_read(i, opcnt, &opr, magic, op_i);
}

// find next instruction that reads opr
// *op_i must be set to -1 by the caller
// on return, *op_i is set to first flag user insn
// returns 1 if exactly 1 flag user is found
static int find_next_flag_use(int i, int opcnt, int magic, int *op_i)
{
  struct parsed_op *po;
  int j, ret = 0;

  for (; i < opcnt; i++)
  {
    if (ops[i].cc_scratch == magic)
      return ret;
    ops[i].cc_scratch = magic;

    po = &ops[i];
    if (po->op == OP_CALL)
      return -1;
    if (po->flags & OPF_JMP) {
      if (po->btj != NULL) {
        // jumptable
        for (j = 0; j < po->btj->count; j++) {
          check_i(po, po->btj->d[j].bt_i);
          ret |= find_next_flag_use(po->btj->d[j].bt_i, opcnt,
                   magic, op_i);
        }
        return ret;
      }

      if (po->flags & OPF_RMD)
        continue;
      check_i(po, po->bt_i);
      if (po->flags & OPF_CJMP)
        goto found;
      else
        i = po->bt_i - 1;
      continue;
    }

    if (!(po->flags & OPF_CC)) {
      if (po->flags & OPF_FLAGS)
        // flags changed
        return ret;
      if (po->flags & OPF_TAIL)
        return ret;
      continue;
    }

found:
    if (*op_i >= 0)
      return -1;

    *op_i = i;
    return 1;
  }

  return 0;
}

static int try_resolve_const(int i, const struct parsed_opr *opr,
  int magic, unsigned int *val)
{
  int s_i = -1;
  int ret;

  ret = resolve_origin(i, opr, magic, &s_i, NULL);
  if (ret == 1) {
    i = s_i;
    if (ops[i].op != OP_MOV && ops[i].operand[1].type != OPT_CONST)
      return -1;

    *val = ops[i].operand[1].val;
    return 1;
  }

  return -1;
}

static int resolve_used_bits(int i, int opcnt, int reg,
  int *mask, int *is_z_check)
{
  struct parsed_opr opr = OPR_INIT(OPT_REG, OPLM_WORD, reg);
  int j = -1, k = -1;
  int ret;

  ret = find_next_read(i, opcnt, &opr, i + opcnt * 20, &j);
  if (ret != 1)
    return -1;

  find_next_read(j + 1, opcnt, &opr, i + opcnt * 20 + 1, &k);
  if (k != -1) {
    fnote(&ops[j], "(first read)\n");
    ferr(&ops[k], "TODO: bit resolve: multiple readers\n");
  }

  if (ops[j].op != OP_TEST || ops[j].operand[1].type != OPT_CONST)
    ferr(&ops[j], "TODO: bit resolve: not a const test\n");

  ferr_assert(&ops[j], ops[j].operand[0].type == OPT_REG);
  ferr_assert(&ops[j], ops[j].operand[0].reg == reg);

  *mask = ops[j].operand[1].val;
  if (ops[j].operand[0].lmod == OPLM_BYTE
    && ops[j].operand[0].name[1] == 'h')
  {
    *mask <<= 8;
  }
  ferr_assert(&ops[j], (*mask & ~0xffff) == 0);

  *is_z_check = 0;
  ret = find_next_flag_use(j + 1, opcnt, i + opcnt * 20 + 2, &k);
  if (ret == 1)
    *is_z_check = ops[k].pfo == PFO_Z;

  return 0;
}

static const struct parsed_proto *resolve_deref(int i, int magic,
  const struct parsed_opr *opr, int level)
{
  const struct parsed_proto *pp = NULL;
  int from_caller = 0;
  char s_reg[4];
  int offset = 0;
  int len = 0;
  int j = -1;
  int k = -1;
  int reg;
  int ret;

  ret = sscanf(opr->name, "%3s+%x%n", s_reg, &offset, &len);
  if (ret != 2 || len != strlen(opr->name)) {
    ret = sscanf(opr->name, "%3s%n", s_reg, &len);
    if (ret != 1 || len != strlen(opr->name))
      return NULL;
  }

  reg = char_array_i(regs_r32, ARRAY_SIZE(regs_r32), s_reg);
  if (reg < 0)
    return NULL;

  ret = resolve_origin_reg(i, reg, i + magic, &j, NULL);
  if (ret != 1)
    return NULL;

  if (ops[j].op == OP_MOV && ops[j].operand[1].type == OPT_REGMEM
    && strlen(ops[j].operand[1].name) == 3
    && ops[j].operand[0].lmod == OPLM_DWORD
    && ops[j].pp == NULL // no hint
    && level == 0)
  {
    // allow one simple dereference (com/directx)
    reg = char_array_i(regs_r32, ARRAY_SIZE(regs_r32),
            ops[j].operand[1].name);
    if (reg < 0)
      return NULL;
    ret = resolve_origin_reg(j, reg, j + magic, &k, NULL);
    if (ret != 1)
      return NULL;
    j = k;
  }
  if (ops[j].op != OP_MOV || ops[j].operand[0].lmod != OPLM_DWORD)
    return NULL;

  if (ops[j].pp != NULL) {
    // type hint in asm
    pp = ops[j].pp;
  }
  else if (ops[j].operand[1].type == OPT_REGMEM) {
    pp = try_recover_pp(&ops[j], &ops[j].operand[1], 0, NULL);
    if (pp == NULL) {
      // maybe structure ptr in structure
      pp = resolve_deref(j, magic, &ops[j].operand[1], level + 1);
    }
  }
  else if (ops[j].operand[1].type == OPT_LABEL)
    pp = proto_parse(g_fhdr, ops[j].operand[1].name, g_quiet_pp);
  else if (ops[j].operand[1].type == OPT_REG) {
    // maybe arg reg?
    k = -1;
    ret = resolve_origin(j, &ops[j].operand[1], i + magic,
            &k, &from_caller);
    if (ret != 1 && from_caller && k == -1 && g_func_pp != NULL) {
      for (k = 0; k < g_func_pp->argc; k++) {
        if (g_func_pp->arg[k].reg == NULL)
          continue;
        if (IS(g_func_pp->arg[k].reg, ops[j].operand[1].name)) {
          pp = g_func_pp->arg[k].pp;
          break;
        }
      }
    }
  }

  if (pp == NULL)
    return NULL;
  if (pp->is_func || pp->is_fptr || !pp->type.is_struct) {
    if (offset != 0)
      ferr(&ops[j], "expected struct, got '%s %s'\n",
           pp->type.name, pp->name);
    return NULL;
  }

  return proto_lookup_struct(g_fhdr, pp->type.name, offset);
}

static const struct parsed_proto *resolve_func_ptr(int i, int opcnt,
  int is_call_op, const struct parsed_opr *opr,
  int *pp_i, int *multi_src)
{
  const struct parsed_proto *pp = NULL;
  int search_advice = 0;

  if (multi_src != NULL)
    *multi_src = 0;
  if (pp_i != NULL)
    *pp_i = -1;

  switch (opr->type) {
  case OPT_REGMEM:
    // try to resolve struct member calls
    pp = resolve_deref(i, i + opcnt * 19, opr, 0);
    if (pp != NULL)
      break;
    // fallthrough
  case OPT_LABEL:
  case OPT_OFFSET:
    pp = try_recover_pp(&ops[i], opr, is_call_op, &search_advice);
    if (!search_advice)
      break;
    // fallthrough
  default:
    scan_for_call_type(i, opr, i + opcnt * 9, is_call_op,
      &pp, pp_i, multi_src);
    break;
  }

  return pp;
}

static struct parsed_proto *process_call_early(int i, int opcnt,
  int *adj_i)
{
  struct parsed_op *po = &ops[i];
  struct parsed_proto *pp;
  int multipath = 0;
  int adj = 0;
  int j, ret;

  pp = po->pp;
  if (pp == NULL || pp->is_vararg || pp->argc_reg != 0)
    // leave for later
    return NULL;

  // look for and make use of esp adjust
  *adj_i = ret = -1;
  if (!pp->is_stdcall && pp->argc_stack > 0)
    ret = scan_for_esp_adjust(i + 1, opcnt,
            pp->argc_stack * 4, &adj, &multipath, 0);
  if (ret >= 0) {
    if (pp->argc_stack > adj / 4)
      return NULL;
    if (multipath)
      return NULL;
    if (ops[ret].op == OP_POP) {
      for (j = 1; j < adj / 4; j++) {
        if (ops[ret + j].op != OP_POP
          || ops[ret + j].operand[0].reg != xCX)
        {
          return NULL;
        }
      }
    }
  }

  *adj_i = ret;
  return pp;
}

static struct parsed_proto *process_call(int i, int opcnt)
{
  struct parsed_op *po = &ops[i];
  const struct parsed_proto *pp_c;
  struct parsed_proto *pp;
  const char *tmpname;
  int call_i = -1, ref_i = -1;
  int adj = 0, multipath = 0;
  int ret, arg;

  tmpname = opr_name(po, 0);
  pp = po->pp;
  if (pp == NULL)
  {
    // indirect call
    pp_c = resolve_func_ptr(i, opcnt, 1, &ops[i].operand[0],
             &call_i, &multipath);
    if (pp_c != NULL) {
      if (!pp_c->is_func && !pp_c->is_fptr)
        ferr(po, "call to non-func: %s\n", pp_c->name);
      pp = proto_clone(pp_c);
      my_assert_not(pp, NULL);
      if (multipath)
        // not resolved just to single func
        pp->is_fptr = 1;

      switch (po->operand[0].type) {
      case OPT_REG:
        // we resolved this call and no longer need the register
        po->regmask_src &= ~(1 << po->operand[0].reg);

        if (!multipath && i != call_i && ops[call_i].op == OP_MOV
          && ops[call_i].operand[1].type == OPT_LABEL)
        {
          // no other source users?
          ret = resolve_last_ref(i, &po->operand[0], i + opcnt * 10,
                  &ref_i);
          if (ret == 1 && call_i == ref_i) {
            // and nothing uses it after us?
            ref_i = -1;
            find_next_read(i + 1, opcnt, &po->operand[0],
              i + opcnt * 11, &ref_i);
            if (ref_i == -1)
              // then also don't need the source mov
              ops[call_i].flags |= OPF_RMD | OPF_NOREGS;
          }
        }
        break;
      case OPT_REGMEM:
        pp->is_fptr = 1;
        break;
      default:
        break;
      }
    }
    if (pp == NULL) {
      pp = calloc(1, sizeof(*pp));
      my_assert_not(pp, NULL);

      pp->is_fptr = 1;
      ret = scan_for_esp_adjust(i + 1, opcnt,
              -1, &adj, &multipath, 0);
      if (ret < 0 || adj < 0) {
        if (!g_allow_regfunc)
          ferr(po, "non-__cdecl indirect call unhandled yet\n");
        pp->is_unresolved = 1;
        adj = 0;
      }
      adj /= 4;
      if (adj > ARRAY_SIZE(pp->arg))
        ferr(po, "esp adjust too large: %d\n", adj);
      pp->ret_type.name = strdup("int");
      pp->argc = pp->argc_stack = adj;
      for (arg = 0; arg < pp->argc; arg++)
        pp->arg[arg].type.name = strdup("int");
    }
    po->pp = pp;
  }

  // look for and make use of esp adjust
  multipath = 0;
  ret = -1;
  if (!pp->is_stdcall && pp->argc_stack > 0) {
    int adj_expect = pp->is_vararg ? -1 : pp->argc_stack * 4;
    ret = scan_for_esp_adjust(i + 1, opcnt,
            adj_expect, &adj, &multipath, 0);
  }
  if (ret >= 0) {
    if (pp->is_vararg) {
      if (adj / 4 < pp->argc_stack) {
        fnote(po, "(this call)\n");
        ferr(&ops[ret], "esp adjust is too small: %x < %x\n",
          adj, pp->argc_stack * 4);
      }
      // modify pp to make it have varargs as normal args
      arg = pp->argc;
      pp->argc += adj / 4 - pp->argc_stack;
      for (; arg < pp->argc; arg++) {
        pp->arg[arg].type.name = strdup("int");
        pp->argc_stack++;
      }
      if (pp->argc > ARRAY_SIZE(pp->arg))
        ferr(po, "too many args for '%s'\n", tmpname);
    }
    if (pp->argc_stack > adj / 4) {
      if (pp->is_noreturn)
        // assume no stack adjust was emited
        goto out;
      fnote(po, "(this call)\n");
      ferr(&ops[ret], "stack tracking failed for '%s': %x %x\n",
        tmpname, pp->argc_stack * 4, adj);
    }

    scan_for_esp_adjust(i + 1, opcnt,
      pp->argc_stack * 4, &adj, &multipath, 1);
  }
  else if (pp->is_vararg)
    ferr(po, "missing esp_adjust for vararg func '%s'\n",
      pp->name);

out:
  return pp;
}

static void check_fptr_args(int i, int opcnt, struct parsed_proto *pp)
{
  struct parsed_opr s_opr = OPR_INIT(OPT_REG, OPLM_DWORD, 0);
  const struct parsed_proto *pp_arg, *pp_cmp;
  const struct parsed_op *po_a;
  const char *s_reg;
  int pp_cmp_i;
  int arg, reg;
  int bad = 0;
  int j;

  for (arg = 0; arg < pp->argc; arg++) {
    pp_cmp = NULL;
    pp_cmp_i = -1;

    pp_arg = pp->arg[arg].pp;
    if (pp_arg == NULL || !pp_arg->is_func)
      continue;

    s_reg = pp->arg[arg].reg;
    if (s_reg != NULL) {
      reg = char_array_i(regs_r32, ARRAY_SIZE(regs_r32), s_reg);
      ferr_assert(&ops[i], reg >= 0);
      s_opr.reg = reg;
      scan_for_call_type(i, &s_opr, i + arg + opcnt * 28, 0,
        &pp_cmp, &pp_cmp_i, NULL);
      if (pp_cmp != NULL && !pp_compatible_func(pp_arg, pp_cmp)) {
        bad = 1;
        if (pp_cmp_i >= 0)
          fnote(&ops[pp_cmp_i], "(referenced here)\n");
      }
    }
    else {
      for (j = 0; j < pp->arg[arg].push_ref_cnt; j++) {
        po_a = pp->arg[arg].push_refs[j];
        if (po_a == NULL || po_a->op != OP_PUSH)
          continue;
        pp_cmp = resolve_func_ptr(po_a - ops, opcnt, 0,
                   &po_a->operand[0], &pp_cmp_i, NULL);
        if (pp_cmp != NULL && !pp_compatible_func(pp_arg, pp_cmp)) {
          bad = 1;
          if (pp_cmp_i < 0)
            pp_cmp_i = po_a - ops;
          if (pp_cmp_i >= 0)
            fnote(&ops[pp_cmp_i], "(referenced here)\n");
        }
      }
    }

    if (bad)
      ferr(&ops[i], "incompatible fptr arg %d\n", arg + 1);
  }
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

static void pp_insert_stack_args(struct parsed_proto *pp, int count)
{
  int a;

  pp->argc += count;
  pp->argc_stack += count;

  for (a = 0; a < pp->argc; a++)
    if (pp->arg[a].type.name == NULL)
      pp->arg[a].type.name = strdup("int");
}

static void pp_add_push_ref(struct parsed_proto *pp,
  int arg, struct parsed_op *po)
{
  pp->arg[arg].push_refs = realloc(pp->arg[arg].push_refs,
                             (pp->arg[arg].push_ref_cnt + 1)
                              * sizeof(pp->arg[arg].push_refs[0]));
  ferr_assert(po, pp->arg[arg].push_refs != NULL);
  pp->arg[arg].push_refs[pp->arg[arg].push_ref_cnt++] = po;
}

static void mark_float_arg(struct parsed_op *po,
  struct parsed_proto *pp, int arg, int *regmask_ffca)
{
  ferr_assert(po, pp->arg[arg].push_ref_cnt == 0);
  pp_add_push_ref(pp, arg, po);

  po->p_argnum = arg + 1;
  po->flags |= OPF_DONE | OPF_FARGNR | OPF_FARG;
  if (regmask_ffca != NULL)
    *regmask_ffca |= 1 << arg;
}

static int check_for_stp(int i, int i_to)
{
  struct parsed_op *po;

  for (; i < i_to; i++) {
    po = &ops[i];
    if (po->op == OP_FST)
      return i;
    if (g_labels[i] != NULL || (po->flags & OPF_JMP))
      return -1;
    if (po->op == OP_CALL || po->op == OP_PUSH || po->op == OP_POP)
      return -1;
    if (po->op == OP_ADD && po->operand[0].reg == xSP)
      return -1;
  }

  return -1;
}

static int collect_call_args_no_push(int i, struct parsed_proto *pp,
  int *regmask_ffca)
{
  struct parsed_op *po;
  int offset = 0;
  int base_arg;
  int j, arg;
  int ret;

  for (base_arg = 0; base_arg < pp->argc; base_arg++)
    if (pp->arg[base_arg].reg == NULL)
      break;

  for (j = i; j > 0; )
  {
    ferr_assert(&ops[j], g_labels[j] == NULL);
    j--;

    po = &ops[j];
    ferr_assert(po, po->op != OP_PUSH);
    if (po->op == OP_FST)
    {
      if (po->operand[0].type != OPT_REGMEM)
        continue;
      ret = parse_stack_esp_offset(po, po->operand[0].name, &offset);
      if (ret != 0)
        continue;
      if (offset < 0 || offset >= pp->argc_stack * 4 || (offset & 3)) {
        //ferr(po, "offset %d, %d args\n", offset, pp->argc_stack);
        continue;
      }

      arg = base_arg + offset / 4;
      mark_float_arg(po, pp, arg, regmask_ffca);
    }
    else if (po->op == OP_SUB && po->operand[0].reg == xSP
      && po->operand[1].type == OPT_CONST)
    {
      po->flags |= OPF_RMD | OPF_DONE | OPF_FARGNR | OPF_FARG;
      break;
    }
  }

  for (arg = base_arg; arg < pp->argc; arg++) {
    ferr_assert(&ops[i], pp->arg[arg].reg == NULL);
    if (pp->arg[arg].push_ref_cnt != 1)
      ferr(&ops[i], "arg %d/%d not found or bad\n", arg, pp->argc);
    po = pp->arg[arg].push_refs[0];
    if (po->operand[0].lmod == OPLM_QWORD)
      arg++;
  }

  return 0;
}

static int collect_call_args_early(int i, int opcnt,
  struct parsed_proto *pp, int *regmask, int *regmask_ffca)
{
  struct parsed_op *po;
  int arg, ret;
  int offset;
  int j, k;

  for (arg = 0; arg < pp->argc; arg++)
    if (pp->arg[arg].reg == NULL)
      break;

  // first see if it can be easily done
  for (j = i; j > 0 && arg < pp->argc; )
  {
    if (g_labels[j] != NULL)
      return -1;
    j--;

    po = &ops[j];
    if (po->op == OP_CALL)
      return -1;
    else if (po->op == OP_ADD && po->operand[0].reg == xSP)
      return -1;
    else if (po->op == OP_POP)
      return -1;
    else if (po->flags & OPF_CJMP)
      return -1;
    else if (po->op == OP_PUSH) {
      if (po->flags & (OPF_FARG|OPF_FARGNR))
        return -1;
      if (!g_header_mode) {
        ret = scan_for_mod(po, j + 1, i, 1);
        if (ret >= 0)
          return -1;
      }

      if (pp->arg[arg].type.is_va_list)
        return -1;

      // next arg
      for (arg++; arg < pp->argc; arg++)
        if (pp->arg[arg].reg == NULL)
          break;
    }
    else if (po->op == OP_SUB && po->operand[0].reg == xSP
      && po->operand[1].type == OPT_CONST)
    {
      if (po->flags & (OPF_RMD|OPF_DONE))
        return -1;
      if (po->operand[1].val != pp->argc_stack * 4)
        ferr(po, "unexpected esp adjust: %d\n",
             po->operand[1].val * 4);
      ferr_assert(po, pp->argc - arg == pp->argc_stack);
      return collect_call_args_no_push(i, pp, regmask_ffca);
    }
  }

  if (arg < pp->argc)
    return -1;

  // now do it
  for (arg = 0; arg < pp->argc; arg++)
    if (pp->arg[arg].reg == NULL)
      break;

  for (j = i; j > 0 && arg < pp->argc; )
  {
    j--;

    if (ops[j].op == OP_PUSH)
    {
      int ref_handled = 0;

      k = check_for_stp(j + 1, i);
      if (k != -1) {
        // push ecx; fstp dword ptr [esp]
        ret = parse_stack_esp_offset(&ops[k],
                ops[k].operand[0].name, &offset);
        if (ret == 0 && offset == 0) {
          if (!pp->arg[arg].type.is_float)
            ferr(&ops[i], "arg %d should be float\n", arg + 1);
          mark_float_arg(&ops[k], pp, arg, regmask_ffca);
          ref_handled = 1;
        }
      }

      if (!ref_handled) {
        ferr_assert(&ops[j], pp->arg[arg].push_ref_cnt == 0);
        pp_add_push_ref(pp, arg, &ops[j]);
      }

      if (regmask != NULL && ops[j].operand[0].type == OPT_REG)
        *regmask |= 1 << ops[j].operand[0].reg;

      ops[j].flags |= OPF_RMD | OPF_DONE | OPF_FARGNR | OPF_FARG;
      ops[j].flags &= ~OPF_RSAVE;

      // next arg
      for (arg++; arg < pp->argc; arg++)
        if (pp->arg[arg].reg == NULL)
          break;
    }
  }

  if (!g_header_mode)
    check_fptr_args(i, opcnt, pp);

  return 0;
}

// ensure all s_a* numbers match for a given func arg in all branches
// returns 1 if any changes were made, 0 if not
static int sync_argnum(struct parsed_proto *pp, int arg,
  int *argnum, int *arggrp)
{
  struct parsed_op *po_tmp;
  int changed = 0;
  int i;

  // see if other branches don't have higher argnum
  for (i = 0; i < pp->arg[arg].push_ref_cnt; i++) {
    po_tmp = pp->arg[arg].push_refs[i];
    if (*argnum < po_tmp->p_argnum)
      *argnum = po_tmp->p_argnum;
    if (*arggrp < po_tmp->p_arggrp)
      *arggrp = po_tmp->p_arggrp;
  }

  // make all argnums consistent
  for (i = 0; i < pp->arg[arg].push_ref_cnt; i++) {
    po_tmp = pp->arg[arg].push_refs[i];
    if (po_tmp->p_argnum == 0)
      continue;
    if (po_tmp->p_argnum != *argnum || po_tmp->p_arggrp != *arggrp) {
      po_tmp->p_argnum = *argnum;
      po_tmp->p_arggrp = *arggrp;
      changed = 1;
    }
  }

  return changed;
}

static int collect_call_args_r(struct parsed_op *po, int i,
  struct parsed_proto *pp, int *regmask,
  int arg, int argnum, int magic,
  int skip, int need_op_saving, int may_reuse)
{
  struct parsed_proto *pp_tmp;
  struct label_ref *lr;
  int need_to_save_current;
  int arg_grp_current = 0;
  int save_args_seen = 0;
  int dummy = 0;
  int ret = 0;
  int reg;
  char buf[32];
  int j, k;

  if (i < 0) {
    ferr(po, "dead label encountered\n");
    return -1;
  }

  for (; arg < pp->argc; arg++, argnum++)
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

    if (g_labels[j] != NULL && g_label_refs[j].i != -1) {
      lr = &g_label_refs[j];
      if (lr->next != NULL)
        need_op_saving = 1;
      for (; lr->next; lr = lr->next) {
        check_i(&ops[j], lr->i);
        if ((ops[lr->i].flags & (OPF_JMP|OPF_CJMP)) != OPF_JMP)
          may_reuse = 1;
        ret = collect_call_args_r(po, lr->i, pp, regmask,
                arg, argnum, magic, skip, need_op_saving, may_reuse);
        if (ret < 0)
          return ret;
      }

      check_i(&ops[j], lr->i);
      if ((ops[lr->i].flags & (OPF_JMP|OPF_CJMP)) != OPF_JMP)
        may_reuse = 1;
      if (j > 0 && LAST_OP(j - 1)) {
        // follow last branch in reverse
        j = lr->i;
        continue;
      }
      need_op_saving = 1;
      ret = collect_call_args_r(po, lr->i, pp, regmask,
              arg, argnum, magic, skip, need_op_saving, may_reuse);
      if (ret < 0)
        return ret;
    }
    j--;

    if (ops[j].op == OP_CALL)
    {
      if (pp->is_unresolved)
        break;

      pp_tmp = ops[j].pp;
      if (pp_tmp == NULL)
        ferr(po, "arg collect %d/%d hit unparsed call '%s'\n",
          arg, pp->argc, ops[j].operand[0].name);
      if (may_reuse && pp_tmp->argc_stack > 0)
        ferr(po, "arg collect %d/%d hit '%s' with %d stack args\n",
          arg, pp->argc, opr_name(&ops[j], 0), pp_tmp->argc_stack);
      if (!pp_tmp->is_unresolved)
        skip = pp_tmp->argc_stack;
    }
    // esp adjust of 0 means we collected it before
    else if (ops[j].op == OP_ADD && ops[j].operand[0].reg == xSP
      && (ops[j].operand[1].type != OPT_CONST
          || ops[j].operand[1].val != 0))
    {
      if (pp->is_unresolved)
        break;

      fnote(po, "(this call)\n");
      ferr(&ops[j], "arg collect %d/%d hit esp adjust of %d\n",
        arg, pp->argc, ops[j].operand[1].val);
    }
    else if (ops[j].op == OP_POP && !(ops[j].flags & OPF_DONE))
    {
      if (pp->is_unresolved)
        break;

      fnote(po, "(this call)\n");
      ferr(&ops[j], "arg collect %d/%d hit pop\n", arg, pp->argc);
    }
    else if (ops[j].flags & OPF_CJMP)
    {
      if (pp->is_unresolved)
        break;

      may_reuse = 1;
    }
    else if (ops[j].op == OP_PUSH && skip > 0) {
      // XXX: might want to rm OPF_FARGNR and only use this
      skip--;
    }
    else if (ops[j].op == OP_PUSH
      && !(ops[j].flags & (OPF_FARGNR|OPF_DONE)))
    {
      if (pp->is_unresolved && (ops[j].flags & OPF_RMD))
        break;

      pp_add_push_ref(pp, arg, &ops[j]);

      sync_argnum(pp, arg, &argnum, &dummy);

      need_to_save_current = 0;
      reg = -1;
      if (ops[j].operand[0].type == OPT_REG)
        reg = ops[j].operand[0].reg;

      if (!need_op_saving) {
        ret = scan_for_mod(&ops[j], j + 1, i, 1);
        need_to_save_current = (ret >= 0);
      }
      if (need_op_saving || need_to_save_current) {
        // mark this arg as one that needs operand saving
        pp->arg[arg].is_saved = 1;

        if (save_args_seen & (1 << (argnum - 1))) {
          save_args_seen = 0;
          arg_grp_current++;
          if (arg_grp_current >= MAX_ARG_GRP)
            ferr(&ops[j], "out of arg groups (arg%d), f %s\n",
              argnum, pp->name);
        }
      }
      else if (ops[j].p_argnum == 0)
        ops[j].flags |= OPF_RMD;

      // some PUSHes are reused by different calls on other branches,
      // but that can't happen if we didn't branch, so they
      // can be removed from future searches (handles nested calls)
      if (!may_reuse)
        ops[j].flags |= OPF_FARGNR;

      ops[j].flags |= OPF_FARG;
      ops[j].flags &= ~OPF_RSAVE;

      // check for __VALIST
      if (!pp->is_unresolved && g_func_pp != NULL
        && pp->arg[arg].type.is_va_list)
      {
        k = -1;
        ret = resolve_origin(j, &ops[j].operand[0],
                magic + 1, &k, NULL);
        if (ret == 1 && k >= 0)
        {
          if (ops[k].op == OP_LEA) {
            if (!g_func_pp->is_vararg)
              ferr(&ops[k], "lea <arg> used, but %s is not vararg?\n",
                   g_func_pp->name);

            snprintf(buf, sizeof(buf), "arg_%X",
              g_func_pp->argc_stack * 4);
            if (strstr(ops[k].operand[1].name, buf)
             || strstr(ops[k].operand[1].name, "arglist"))
            {
              ops[k].flags |= OPF_RMD | OPF_NOREGS | OPF_DONE;
              ops[j].flags |= OPF_RMD | OPF_NOREGS | OPF_VAPUSH;
              pp->arg[arg].is_saved = 0;
              reg = -1;
            }
            else
              ferr(&ops[k], "va_list arg detection failed\n");
          }
          // check for va_list from g_func_pp arg too
          else if (ops[k].op == OP_MOV
            && is_stack_access(&ops[k], &ops[k].operand[1]))
          {
            ret = stack_frame_access(&ops[k], &ops[k].operand[1],
              buf, sizeof(buf), ops[k].operand[1].name, "", 1, 0);
            if (ret >= 0) {
              ops[k].flags |= OPF_RMD | OPF_DONE;
              ops[j].flags |= OPF_RMD;
              ops[j].p_argpass = ret + 1;
              pp->arg[arg].is_saved = 0;
              reg = -1;
            }
          }
        }
      }

      if (pp->arg[arg].is_saved) {
        ops[j].flags &= ~OPF_RMD;
        ops[j].p_argnum = argnum;
        ops[j].p_arggrp = arg_grp_current;
      }

      // tracking reg usage
      if (reg >= 0)
        *regmask |= 1 << reg;

      arg++;
      argnum++;
      if (!pp->is_unresolved) {
        // next arg
        for (; arg < pp->argc; arg++, argnum++)
          if (pp->arg[arg].reg == NULL)
            break;
      }
      magic = (magic & 0xffffff) | (arg << 24);
    }

    if (ops[j].p_arggrp > arg_grp_current) {
      save_args_seen = 0;
      arg_grp_current = ops[j].p_arggrp;
    }
    if (ops[j].p_argnum > 0)
      save_args_seen |= 1 << (ops[j].p_argnum - 1);
  }

  if (arg < pp->argc) {
    ferr(po, "arg collect failed for '%s': %d/%d\n",
      pp->name, arg, pp->argc);
    return -1;
  }

  return arg;
}

static int collect_call_args(struct parsed_op *po, int i, int opcnt,
  struct parsed_proto *pp, int *regmask, int magic)
{
  int ret;

  ret = collect_call_args_r(po, i, pp, regmask, 0, 1, magic,
          0, 0, 0);
  if (ret < 0)
    return ret;

  if (pp->is_unresolved)
    pp_insert_stack_args(pp, ret);

  // note: p_argnum, p_arggrp will be propagated in a later pass,
  // look for sync_argnum() (p_arggrp is for cases when mixed pushes
  // for multiple funcs are going on)

  if (!g_header_mode)
    check_fptr_args(i, opcnt, pp);

  return ret;
}

static void reg_use_pass(int i, int opcnt, unsigned char *cbits,
  int regmask_now, int *regmask,
  int regmask_save_now, int *regmask_save,
  int *regmask_init, int regmask_arg)
{
  struct parsed_op *po;
  int already_saved;
  int regmask_new;
  int regmask_op;
  int flags_set;
  int ret, reg;
  int j;

  for (; i < opcnt; i++)
  {
    po = &ops[i];
    if (cbits[i >> 3] & (1 << (i & 7)))
      return;
    cbits[i >> 3] |= (1 << (i & 7));

    if ((po->flags & OPF_JMP) && po->op != OP_CALL) {
      if (po->flags & (OPF_RMD|OPF_DONE))
        continue;
      if (po->btj != NULL) {
        for (j = 0; j < po->btj->count; j++) {
          check_i(po, po->btj->d[j].bt_i);
          reg_use_pass(po->btj->d[j].bt_i, opcnt, cbits,
            regmask_now, regmask, regmask_save_now, regmask_save,
            regmask_init, regmask_arg);
        }
        return;
      }

      check_i(po, po->bt_i);
      if (po->flags & OPF_CJMP)
        reg_use_pass(po->bt_i, opcnt, cbits,
          regmask_now, regmask, regmask_save_now, regmask_save,
          regmask_init, regmask_arg);
      else
        i = po->bt_i - 1;
      continue;
    }

    if (po->op == OP_PUSH && !(po->flags & (OPF_FARG|OPF_DONE))
      && !g_func_pp->is_userstack
      && po->operand[0].type == OPT_REG)
    {
      int save_level = 0;

      reg = po->operand[0].reg;
      ferr_assert(po, reg >= 0);

      already_saved = 0;
      flags_set = OPF_RSAVE | OPF_RMD | OPF_DONE;
      if (regmask_now & (1 << reg)) {
        already_saved = regmask_save_now & (1 << reg);
        flags_set = OPF_RSAVE | OPF_DONE;
        save_level++;
      }

      ret = scan_for_pop(i + 1, opcnt, i + opcnt * 3,
              reg, 0, 0, save_level, 0);
      if (ret == 1) {
        scan_for_pop(i + 1, opcnt, i + opcnt * 4,
          reg, 0, 0, save_level, flags_set);
      }
      else {
        ret = scan_for_pop_ret(i + 1, opcnt, po->operand[0].reg, 0);
        if (ret == 1) {
          scan_for_pop_ret(i + 1, opcnt, po->operand[0].reg,
            flags_set);
        }
      }
      if (ret == 1) {
        ferr_assert(po, !already_saved);
        po->flags |= flags_set;

        if (regmask_now & (1 << reg)) {
          regmask_save_now |= (1 << reg);
          *regmask_save |= regmask_save_now;
        }
        continue;
      }
    }
    else if (po->op == OP_POP && (po->flags & OPF_RSAVE)) {
      reg = po->operand[0].reg;
      ferr_assert(po, reg >= 0);

      if (regmask_save_now & (1 << reg))
        regmask_save_now &= ~(1 << reg);
      else
        regmask_now &= ~(1 << reg);
      continue;
    }
    else if (po->op == OP_CALL) {
      if ((po->regmask_dst & (1 << xAX))
        && !(po->regmask_dst & (1 << xDX)))
      {
        if (po->flags & OPF_TAIL)
          // don't need eax, will do "return f();" or "f(); return;"
          po->regmask_dst &= ~(1 << xAX);
        else {
          find_next_read_reg(i + 1, opcnt, xAX, OPLM_DWORD,
            i + opcnt * 17, &j);
          if (j == -1)
            // not used
            po->regmask_dst &= ~(1 << xAX);
        }
      }

      // not "full stack" mode and have something in stack
      if (!(regmask_now & mxST7_2) && (regmask_now & mxST1_0))
        ferr(po, "float stack is not empty on func call\n");
    }

    if (po->flags & OPF_NOREGS)
      continue;

    // if incomplete register is used, clear it on init to avoid
    // later use of uninitialized upper part in some situations
    if ((po->flags & OPF_DATA) && po->operand[0].type == OPT_REG
        && po->operand[0].lmod != OPLM_DWORD)
    {
      reg = po->operand[0].reg;
      ferr_assert(po, reg >= 0);

      if (!(regmask_now & (1 << reg)))
        *regmask_init |= 1 << reg;
    }

    regmask_op = po->regmask_src | po->regmask_dst;

    regmask_new = po->regmask_src & ~regmask_now & ~regmask_arg;
    regmask_new &= ~(1 << xSP);
    if (g_bp_frame && !(po->flags & OPF_EBP_S))
      regmask_new &= ~(1 << xBP);

    if (regmask_new != 0)
      fnote(po, "uninitialized reg mask: %x\n", regmask_new);

    if (regmask_op & (1 << xBP)) {
      if (g_bp_frame && !(po->flags & OPF_EBP_S)) {
        if (po->regmask_dst & (1 << xBP))
          // compiler decided to drop bp frame and use ebp as scratch
          scan_fwd_set_flags(i + 1, opcnt, i + opcnt * 5, OPF_EBP_S);
        else
          regmask_op &= ~(1 << xBP);
      }
    }

    if (po->flags & OPF_FPUSH) {
      if (regmask_now & mxST1)
        regmask_now |= mxSTa; // switch to "full stack" mode
      if (regmask_now & mxSTa)
        po->flags |= OPF_FSHIFT;
      if (!(regmask_now & mxST7_2)) {
        regmask_now =
          (regmask_now & ~mxST1_0) | ((regmask_now & mxST0) << 1);
      }
    }

    regmask_now |= regmask_op;
    *regmask |= regmask_now;

    // released regs
    if (po->flags & OPF_FPOPP) {
      if ((regmask_now & mxSTa) == 0)
        ferr(po, "float pop on empty stack?\n");
      if (regmask_now & mxST7_2)
        po->flags |= OPF_FSHIFT;
      if (!(regmask_now & mxST7_2))
        regmask_now &= ~mxST1_0;
    }
    else if (po->flags & OPF_FPOP) {
      if ((regmask_now & mxSTa) == 0)
        ferr(po, "float pop on empty stack?\n");
      if (regmask_now & (mxST7_2 | mxST1))
        po->flags |= OPF_FSHIFT;
      if (!(regmask_now & mxST7_2)) {
        regmask_now =
          (regmask_now & ~mxST1_0) | ((regmask_now & mxST1) >> 1);
      }
    }

    if (po->flags & OPF_TAIL) {
      if (!(regmask_now & mxST7_2)) {
        if (get_pp_arg_regmask_dst(g_func_pp) & mxST0) {
          if (!(regmask_now & mxST0))
            ferr(po, "no st0 on float return, mask: %x\n",
                 regmask_now);
        }
        else if (regmask_now & mxST1_0)
          ferr(po, "float regs on tail: %x\n", regmask_now);
      }

      // there is support for "conditional tailcall", sort of
      if (!(po->flags & OPF_CC))
        return;
    }
  }
}

static void output_std_flag_z(FILE *fout, struct parsed_op *po,
  int *pfomask, const char *dst_opr_text)
{
  if (*pfomask & (1 << PFO_Z)) {
    fprintf(fout, "\n  cond_z = (%s%s == 0);",
      lmod_cast_u(po, po->operand[0].lmod), dst_opr_text);
    *pfomask &= ~(1 << PFO_Z);
  }
}

static void output_std_flag_s(FILE *fout, struct parsed_op *po,
  int *pfomask, const char *dst_opr_text)
{
  if (*pfomask & (1 << PFO_S)) {
    fprintf(fout, "\n  cond_s = (%s%s < 0);",
      lmod_cast_s(po, po->operand[0].lmod), dst_opr_text);
    *pfomask &= ~(1 << PFO_S);
  }
}

static void output_std_flags(FILE *fout, struct parsed_op *po,
  int *pfomask, const char *dst_opr_text)
{
  output_std_flag_z(fout, po, pfomask, dst_opr_text);
  output_std_flag_s(fout, po, pfomask, dst_opr_text);
}

enum {
  OPP_FORCE_NORETURN = (1 << 0),
  OPP_SIMPLE_ARGS    = (1 << 1),
  OPP_ALIGN          = (1 << 2),
};

static void output_pp_attrs(FILE *fout, const struct parsed_proto *pp,
  int flags)
{
  const char *cconv = "";

  if (pp->is_fastcall)
    cconv = "__fastcall ";
  else if (pp->is_stdcall && pp->argc_reg == 0)
    cconv = "__stdcall ";

  fprintf(fout, (flags & OPP_ALIGN) ? "%-16s" : "%s", cconv);

  if (pp->is_noreturn || (flags & OPP_FORCE_NORETURN))
    fprintf(fout, "noreturn ");
}

static void output_pp(FILE *fout, const struct parsed_proto *pp,
  int flags)
{
  int i;

  fprintf(fout, (flags & OPP_ALIGN) ? "%-5s" : "%s ",
    pp->ret_type.name);
  if (pp->is_fptr)
    fprintf(fout, "(");
  output_pp_attrs(fout, pp, flags);
  if (pp->is_fptr)
    fprintf(fout, "*");
  fprintf(fout, "%s", pp->name);
  if (pp->is_fptr)
    fprintf(fout, ")");

  fprintf(fout, "(");
  for (i = 0; i < pp->argc; i++) {
    if (i > 0)
      fprintf(fout, ", ");
    if (pp->arg[i].pp != NULL && pp->arg[i].pp->is_func
      && !(flags & OPP_SIMPLE_ARGS))
    {
      // func pointer
      output_pp(fout, pp->arg[i].pp, 0);
    }
    else if (pp->arg[i].type.is_retreg) {
      fprintf(fout, "u32 *r_%s", pp->arg[i].reg);
    }
    else {
      fprintf(fout, "%s", pp->arg[i].type.name);
      if (!pp->is_fptr)
        fprintf(fout, " a%d", i + 1);
    }

    if (pp->arg[i].type.is_64bit)
      i++;
  }
  if (pp->is_vararg) {
    if (i > 0)
      fprintf(fout, ", ");
    fprintf(fout, "...");
  }
  fprintf(fout, ")");
}

static char *saved_arg_name(char *buf, size_t buf_size, int grp, int num)
{
  char buf1[16];

  buf1[0] = 0;
  if (grp > 0)
    snprintf(buf1, sizeof(buf1), "%d", grp);
  snprintf(buf, buf_size, "s%s_a%d", buf1, num);

  return buf;
}

static void gen_x_cleanup(int opcnt);

static void gen_func(FILE *fout, FILE *fhdr, const char *funcn, int opcnt)
{
  struct parsed_op *po, *delayed_flag_op = NULL, *tmp_op;
  struct parsed_opr *last_arith_dst = NULL;
  char buf1[256], buf2[256], buf3[256], cast[64];
  struct parsed_proto *pp, *pp_tmp;
  struct parsed_data *pd;
  int save_arg_vars[MAX_ARG_GRP] = { 0, };
  unsigned char cbits[MAX_OPS / 8];
  const char *float_type;
  const char *float_st0;
  const char *float_st1;
  int need_float_stack = 0;
  int need_float_sw = 0; // status word
  int need_tmp_var = 0;
  int need_tmp64 = 0;
  int cond_vars = 0;
  int had_decl = 0;
  int label_pending = 0;
  int need_double = 0;
  int stack_align = 0;
  int stack_fsz_adj = 0;
  int lock_handled = 0;
  int regmask_save = 0; // used regs saved/restored in this func
  int regmask_arg;      // regs from this function args (fastcall, etc)
  int regmask_ret;      // regs needed on ret
  int regmask_now;      // temp
  int regmask_init = 0; // regs that need zero initialization
  int regmask_pp = 0;   // regs used in complex push-pop graph
  int regmask_ffca = 0; // float function call args
  int regmask = 0;      // used regs
  int pfomask = 0;
  int found = 0;
  int dead_dst;
  int no_output;
  int i, j, l;
  int arg;
  int reg;
  int ret;

  g_bp_frame = g_sp_frame = g_stack_fsz = 0;
  g_stack_frame_used = 0;
  g_seh_size = 0;
  if (g_sct_func_attr & SCTFA_CLEAR_REGS)
    regmask_init = g_regmask_init;

  g_func_pp = proto_parse(fhdr, funcn, 0);
  if (g_func_pp == NULL)
    ferr(ops, "proto_parse failed for '%s'\n", funcn);

  regmask_arg = get_pp_arg_regmask_src(g_func_pp);
  regmask_ret = get_pp_arg_regmask_dst(g_func_pp);

  // pass1:
  // - resolve all branches
  // - parse calls with labels
  resolve_branches_parse_calls(opcnt);

  // pass2:
  // - handle ebp/esp frame, remove ops related to it
  scan_prologue_epilogue(opcnt, &stack_align);

  // handle a case where sf size is unalignment, but is
  // placed in a way that elements are still aligned
  if (g_stack_fsz & 4) {
    for (i = 0; i < g_eqcnt; i++) {
      if (g_eqs[i].lmod != OPLM_QWORD)
        continue;
      if (!(g_eqs[i].offset & 4)) {
        g_stack_fsz += 4;
        stack_fsz_adj = 4;
      }
      break;
    }
  }

  // pass3:
  // - remove dead labels
  // - set regs needed at ret
  for (i = 0; i < opcnt; i++)
  {
    if (g_labels[i] != NULL && g_label_refs[i].i == -1) {
      free(g_labels[i]);
      g_labels[i] = NULL;
    }

    if (ops[i].op == OP_RET)
      ops[i].regmask_src |= regmask_ret;
  }

  // pass4:
  // - process trivial calls
  for (i = 0; i < opcnt; i++)
  {
    po = &ops[i];
    if (po->flags & (OPF_RMD|OPF_DONE))
      continue;

    if (po->op == OP_CALL)
    {
      pp = process_call_early(i, opcnt, &j);
      if (pp != NULL) {
        if (!(po->flags & OPF_ATAIL)) {
          // since we know the args, try to collect them
          ret = collect_call_args_early(i, opcnt, pp,
                  &regmask, &regmask_ffca);
          if (ret != 0)
            pp = NULL;
        }
      }

      if (pp != NULL) {
        if (j >= 0) {
          // commit esp adjust
          if (ops[j].op != OP_POP)
            patch_esp_adjust(&ops[j], pp->argc_stack * 4);
          else {
            for (l = 0; l < pp->argc_stack; l++)
              ops[j + l].flags |= OPF_DONE | OPF_RMD | OPF_NOREGS;
          }
        }

        if (strstr(pp->ret_type.name, "int64"))
          need_tmp64 = 1;

        po->flags |= OPF_DONE;
      }
    }
  }

  // pass5:
  // - process calls, stage 2
  // - handle some push/pop pairs
  // - scan for STD/CLD, propagate DF
  // - try to resolve needed x87 status word bits
  for (i = 0; i < opcnt; i++)
  {
    int mask, z_check;

    po = &ops[i];
    if (po->flags & OPF_RMD)
      continue;

    if (po->op == OP_CALL)
    {
      if (!(po->flags & OPF_DONE)) {
        pp = process_call(i, opcnt);

        if (!pp->is_unresolved && !(po->flags & OPF_ATAIL)) {
          // since we know the args, collect them
          collect_call_args(po, i, opcnt, pp, &regmask, i + opcnt * 2);
        }
        // for unresolved, collect after other passes
      }

      pp = po->pp;
      ferr_assert(po, pp != NULL);

      po->regmask_src |= get_pp_arg_regmask_src(pp);
      po->regmask_dst |= get_pp_arg_regmask_dst(pp);

      if (po->regmask_dst & mxST0)
        po->flags |= OPF_FPUSH;

      if (strstr(pp->ret_type.name, "int64"))
        need_tmp64 = 1;

      continue;
    }

    if (po->flags & OPF_DONE)
      continue;

    switch (po->op) {
    case OP_PUSH:
      if (!(po->flags & OPF_FARG) && !(po->flags & OPF_RSAVE)
        && po->operand[0].type == OPT_CONST)
      {
        scan_for_pop_const(i, opcnt, i + opcnt * 12);
      }
      break;

    case OP_POP:
      scan_pushes_for_pop(i, opcnt, &regmask_pp);
      break;

    case OP_STD:
      po->flags |= OPF_DF | OPF_RMD | OPF_DONE;
      scan_propagate_df(i + 1, opcnt);
      break;

    case OP_FNSTSW:
      need_float_sw = 1;
      if (po->operand[0].type != OPT_REG || po->operand[0].reg != xAX)
        ferr(po, "TODO: fnstsw to mem\n");
      ret = resolve_used_bits(i + 1, opcnt, xAX, &mask, &z_check);
      if (ret != 0)
        ferr(po, "fnstsw resolve failed\n");
      ret = adjust_prev_op(i, OP_FCOM, i + opcnt * 21,
              (void *)(long)(mask | (z_check << 16)));
      if (ret != 1)
        ferr(po, "failed to find fcom: %d\n", ret);
      break;

    default:
      break;
    }
  }

  // pass6:
  // - find POPs for PUSHes, rm both
  // - scan for all used registers
  memset(cbits, 0, sizeof(cbits));
  reg_use_pass(0, opcnt, cbits, regmask_init, &regmask,
    0, &regmask_save, &regmask_init, regmask_arg);

  need_float_stack = !!(regmask & mxST7_2);

  // pass7:
  // - find flag set ops for their users
  // - do unresolved calls
  // - declare indirect functions
  // - other op specific processing
  for (i = 0; i < opcnt; i++)
  {
    po = &ops[i];
    if (po->flags & (OPF_RMD|OPF_DONE))
      continue;

    if (po->flags & OPF_CC)
    {
      int setters[16], cnt = 0, branched = 0;

      ret = scan_for_flag_set(i, opcnt, i + opcnt * 6,
              &branched, setters, &cnt);
      if (ret < 0 || cnt <= 0)
        ferr(po, "unable to trace flag setter(s)\n");
      if (cnt > ARRAY_SIZE(setters))
        ferr(po, "too many flag setters\n");

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
            pfomask = 1 << po->pfo;
        }
        else if (tmp_op->op == OP_CMPS || tmp_op->op == OP_SCAS) {
          pfomask = 1 << po->pfo;
        }
        else {
          // see if we'll be able to handle based on op result
          if ((tmp_op->op != OP_AND && tmp_op->op != OP_OR
               && po->pfo != PFO_Z && po->pfo != PFO_S
               && po->pfo != PFO_P)
              || branched
              || scan_for_mod_opr0(tmp_op, setters[j] + 1, i) >= 0)
          {
            pfomask = 1 << po->pfo;
          }

          if (tmp_op->op == OP_ADD && po->pfo == PFO_C) {
            propagate_lmod(tmp_op, &tmp_op->operand[0],
              &tmp_op->operand[1]);
            if (tmp_op->operand[0].lmod == OPLM_DWORD)
              need_tmp64 = 1;
          }
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

    switch (po->op) {
    case OP_CMPS:
    case OP_SCAS:
      cond_vars |= 1 << PFO_Z;
      break;

    case OP_MUL:
      if (po->operand[0].lmod == OPLM_DWORD)
        need_tmp64 = 1;
      break;

    case OP_IMUL:
      if (po->operand_cnt == 1 && po->operand[0].lmod == OPLM_DWORD)
        need_tmp64 = 1;
      break;

    case OP_CALL:
      // note: resolved non-reg calls are OPF_DONE already
      pp = po->pp;
      ferr_assert(po, pp != NULL);

      if (pp->is_unresolved) {
        int regmask_stack = 0;

        if ((po->flags & OPF_TAIL) && g_func_pp->is_stdcall)
          pp_insert_stack_args(pp, g_func_pp->argc_stack);
        else {
          collect_call_args(po, i, opcnt, pp, &regmask, i + opcnt * 2);

          // this is pretty rough guess:
          // see ecx and edx were pushed (and not their saved versions)
          for (arg = 0; arg < pp->argc; arg++) {
            if (pp->arg[arg].reg != NULL && !pp->arg[arg].is_saved)
              continue;

            if (pp->arg[arg].push_ref_cnt == 0)
              ferr(po, "parsed_op missing for arg%d\n", arg);
            tmp_op = pp->arg[arg].push_refs[0];
            if (tmp_op->operand[0].type == OPT_REG)
              regmask_stack |= 1 << tmp_op->operand[0].reg;
          }
        }

        // quick dumb check for potential reg-args
        for (j = i - 1; j >= 0 && ops[j].op == OP_MOV; j--)
          if (ops[j].operand[0].type == OPT_REG)
            regmask_stack &= ~(1 << ops[j].operand[0].reg);

        if ((regmask_stack & (mxCX|mxDX)) != (mxCX|mxDX)
            && ((regmask | regmask_arg) & (mxCX|mxDX)))
        {
          if (pp->argc_stack != 0
              || ((regmask | regmask_arg) & (mxCX|mxDX)))
          {
            pp_insert_reg_arg(pp, "ecx");
            pp->is_fastcall = 1;
            regmask_init |= 1 << xCX;
            regmask |= 1 << xCX;
          }
          if (pp->argc_stack != 0
              || ((regmask | regmask_arg) & mxDX))
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
      if (!(po->flags & OPF_TAIL)
          && !(g_sct_func_attr & SCTFA_NOWARN) && !g_nowarn_reguse)
      {
        // treat al write as overwrite to avoid many false positives
        if (IS(pp->ret_type.name, "void") || pp->ret_type.is_float) {
          find_next_read_reg(i + 1, opcnt, xAX, OPLM_BYTE,
            i + opcnt * 25, &j);
          if (j != -1) {
            fnote(po, "eax used after void/float ret call\n");
            fnote(&ops[j], "(used here)\n");
          }
        }
        if (!strstr(pp->ret_type.name, "int64")) {
          find_next_read_reg(i + 1, opcnt, xDX, OPLM_BYTE,
            i + opcnt * 26, &j);
          // indirect calls are often guessed, don't warn
          if (j != -1 && !IS_OP_INDIRECT_CALL(&ops[j])) {
            fnote(po, "edx used after 32bit ret call\n");
            fnote(&ops[j], "(used here)\n");
          }
        }
        j = 1;
        // msvc often relies on callee not modifying 'this'
        for (arg = 0; arg < pp->argc; arg++) {
          if (pp->arg[arg].reg && IS(pp->arg[arg].reg, "ecx")) {
            j = 0;
            break;
          }
        }
        if (j != 0) {
          find_next_read_reg(i + 1, opcnt, xCX, OPLM_BYTE,
            i + opcnt * 27, &j);
          if (j != -1 && !IS_OP_INDIRECT_CALL(&ops[j])) {
            fnote(po, "ecx used after call\n");
            fnote(&ops[j], "(used here)\n");
          }
        }
      }
      break;

    case OP_MOV:
      if (po->operand[0].pp != NULL && po->operand[1].pp != NULL)
      {
        // <var> = offset <something>
        if ((po->operand[1].pp->is_func || po->operand[1].pp->is_fptr)
          && !IS_START(po->operand[1].name, "off_"))
        {
          if (!po->operand[0].pp->is_fptr)
            ferr(po, "%s not declared as fptr when it should be\n",
              po->operand[0].name);
          if (pp_cmp_func(po->operand[0].pp, po->operand[1].pp)) {
            pp_print(buf1, sizeof(buf1), po->operand[0].pp);
            pp_print(buf2, sizeof(buf2), po->operand[1].pp);
            fnote(po, "var:  %s\n", buf1);
            fnote(po, "func: %s\n", buf2);
            ferr(po, "^ mismatch\n");
          }
        }
      }
      break;

    case OP_DIV:
    case OP_IDIV:
      if (po->operand[0].lmod == OPLM_DWORD) {
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
      else
        need_tmp_var = 1;
      break;

    case OP_CLD:
      po->flags |= OPF_RMD | OPF_DONE;
      break;

    case OP_RCL:
    case OP_RCR:
    case OP_XCHG:
      need_tmp_var = 1;
      break;

    case OP_FLD:
      if (po->operand[0].lmod == OPLM_QWORD)
        need_double = 1;
      break;

    case OP_RDTSC:
    case OPP_ALLSHL:
    case OPP_ALLSHR:
      need_tmp64 = 1;
      break;

    case OPP_FTOL:
      find_next_read_reg(i + 1, opcnt, xDX, OPLM_DWORD,
        i + opcnt * 18, &j);
      if (j == -1)
        po->flags |= OPF_32BIT;
      break;

    default:
      break;
    }
  }

  // pass8: sync all push arg numbers
  // some calls share args and not all of them
  // (there's only partial intersection)
  do {
    int changed, argnum, arggrp;

    found = 0;
    for (i = 0; i < opcnt; i++)
    {
      po = &ops[i];
      if ((po->flags & (OPF_RMD|OPF_DONE)) || po->op != OP_CALL)
        continue;

      pp = po->pp;
      arggrp = 0;
      do {
        changed = 0;
        for (arg = argnum = 0; arg < pp->argc; arg++) {
          if (pp->arg[arg].reg != NULL)
            continue;
          if (pp->arg[arg].is_saved)
            changed |= sync_argnum(pp, arg, &argnum, &arggrp);
          argnum++;
        }
        found |= changed;
      }
      while (changed);

      if (argnum > 32)
        ferr(po, "too many args or looping in graph\n");
    }
  }
  while (found);

  // pass9: final adjustments
  for (i = 0; i < opcnt; i++)
  {
    po = &ops[i];
    if (po->flags & (OPF_RMD|OPF_DONE))
      continue;

    if (po->op != OP_FST && po->p_argnum > 0)
      save_arg_vars[po->p_arggrp] |= 1 << (po->p_argnum - 1);

    // correct for "full stack" mode late enable
    if ((po->flags & (OPF_PPUSH|OPF_FPOP|OPF_FPOPP))
        && need_float_stack)
      po->flags |= OPF_FSHIFT;
  }

  float_type = need_double ? "double" : "float";
  float_st0 = need_float_stack ? "f_st[f_stp & 7]" : "f_st0";
  float_st1 = need_float_stack ? "f_st[(f_stp + 1) & 7]" : "f_st1";

  // output starts here

  if (g_seh_found)
    fprintf(fout, "// had SEH\n");

  // define userstack size
  if (g_func_pp->is_userstack) {
    fprintf(fout, "#ifndef US_SZ_%s\n", g_func_pp->name);
    fprintf(fout, "#define US_SZ_%s USERSTACK_SIZE\n", g_func_pp->name);
    fprintf(fout, "#endif\n");
  }

  // the function itself
  ferr_assert(ops, !g_func_pp->is_fptr);
  output_pp(fout, g_func_pp,
    (g_ida_func_attr & IDAFA_NORETURN) ? OPP_FORCE_NORETURN : 0);
  fprintf(fout, "\n{\n");

  // declare indirect functions
  for (i = 0; i < opcnt; i++) {
    po = &ops[i];
    if (po->flags & OPF_RMD)
      continue;

    if (po->op == OP_CALL) {
      pp = po->pp;
      if (pp == NULL)
        ferr(po, "NULL pp\n");

      if (pp->is_fptr && !(pp->name[0] != 0 && pp->is_arg)) {
        if (pp->name[0] != 0) {
          if (IS_START(pp->name, "guess"))
            pp->is_guessed = 1;

          memmove(pp->name + 2, pp->name, strlen(pp->name) + 1);
          memcpy(pp->name, "i_", 2);

          // might be declared already
          found = 0;
          for (j = 0; j < i; j++) {
            if (ops[j].op == OP_CALL && (pp_tmp = ops[j].pp)) {
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

        fprintf(fout, "  ");
        output_pp(fout, pp, OPP_SIMPLE_ARGS);
        fprintf(fout, ";\n");
      }
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
    had_decl = 1;
  }

  // declare stack frame, va_arg
  if (g_stack_fsz) {
    if (stack_fsz_adj)
      fprintf(fout, "  // stack_fsz_adj %d\n", stack_fsz_adj);

    fprintf(fout, "  union { u32 d[%d];", (g_stack_fsz + 3) / 4);
    if (g_func_lmods & (1 << OPLM_WORD))
      fprintf(fout, " u16 w[%d];", (g_stack_fsz + 1) / 2);
    if (g_func_lmods & (1 << OPLM_BYTE))
      fprintf(fout, " u8 b[%d];", g_stack_fsz);
    if (g_func_lmods & (1 << OPLM_QWORD))
      fprintf(fout, " double q[%d];", (g_stack_fsz + 7) / 8);

    if (stack_align > 8)
      ferr(ops, "unhandled stack align of %d\n", stack_align);
    else if (stack_align == 8)
      fprintf(fout, " u64 align;");
    fprintf(fout, " } sf;\n");
    had_decl = 1;
  }

  if ((g_sct_func_attr & SCTFA_ARGFRAME) && g_func_pp->argc_stack) {
    fprintf(fout, "  struct { u32 ");
    for (i = j = 0; i < g_func_pp->argc; i++) {
      if (g_func_pp->arg[i].reg != NULL)
        continue;
      if (j++ != 0)
        fprintf(fout, ", ");
      fprintf(fout, "a%d", i + 1);
    }
    fprintf(fout, "; } af = {\n    ");
    for (i = j = 0; i < g_func_pp->argc; i++) {
      if (g_func_pp->arg[i].reg != NULL)
        continue;
      if (j++ != 0)
        fprintf(fout, ", ");
        if (g_func_pp->arg[i].type.is_ptr)
          fprintf(fout, "(u32)");
      fprintf(fout, "a%d", i + 1);
    }
    fprintf(fout, "\n  };\n");
  }

  if (g_func_pp->is_userstack) {
    fprintf(fout, "  u32 fake_sf[US_SZ_%s / 4];\n", g_func_pp->name);
    fprintf(fout, "  u32 *esp = &fake_sf[sizeof(fake_sf) / 4];\n");
    had_decl = 1;
  }

  if (g_func_pp->is_vararg) {
    fprintf(fout, "  va_list ap;\n");
    had_decl = 1;
  }

  // declare arg-registers
  for (i = 0; i < g_func_pp->argc; i++) {
    if (g_func_pp->arg[i].reg != NULL) {
      reg = char_array_i(regs_r32,
              ARRAY_SIZE(regs_r32), g_func_pp->arg[i].reg);
      if (regmask & (1 << reg)) {
        if (g_func_pp->arg[i].type.is_retreg)
          fprintf(fout, "  u32 %s = *r_%s;\n",
            g_func_pp->arg[i].reg, g_func_pp->arg[i].reg);
        else
          fprintf(fout, "  u32 %s = (u32)a%d;\n",
            g_func_pp->arg[i].reg, i + 1);
      }
      else {
        if (g_func_pp->arg[i].type.is_retreg)
          ferr(ops, "retreg '%s' is unused?\n",
            g_func_pp->arg[i].reg);
        fprintf(fout, "  // %s = a%d; // unused\n",
          g_func_pp->arg[i].reg, i + 1);
      }
      had_decl = 1;
    }
  }

  // declare normal registers
  regmask_now = regmask & ~regmask_arg & ~g_regmask_rm;
  regmask_now &= ~(1 << xSP);
  if (regmask_now & 0x00ff) {
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
  // ... mmx
  if (regmask_now & 0xff00) {
    for (reg = 8; reg < 16; reg++) {
      if (regmask_now & (1 << reg)) {
        fprintf(fout, "  mmxr %s", regs_r32[reg]);
        if (regmask_init & (1 << reg))
          fprintf(fout, " = { 0, }");
        fprintf(fout, ";\n");
        had_decl = 1;
      }
    }
  }
  // ... x87
  if (need_float_stack) {
    fprintf(fout, "  %s f_st[8];\n", float_type);
    fprintf(fout, "  int f_stp = 0;\n");
    had_decl = 1;
  }
  else {
    if (regmask_now & 0xff0000) {
      for (reg = 16; reg < 24; reg++) {
        if (regmask_now & (1 << reg)) {
          fprintf(fout, "  %s f_st%d", float_type, reg - 16);
          if (regmask_init & (1 << reg))
            fprintf(fout, " = 0");
          fprintf(fout, ";\n");
          had_decl = 1;
        }
      }
    }
  }

  if (need_float_sw) {
    fprintf(fout, "  u16 f_sw;\n");
    had_decl = 1;
  }

  if (regmask_save) {
    for (reg = 0; reg < 8; reg++) {
      if (regmask_save & (1 << reg)) {
        fprintf(fout, "  u32 s_%s;\n", regs_r32[reg]);
        had_decl = 1;
      }
    }
  }

  for (i = 0; i < ARRAY_SIZE(save_arg_vars); i++) {
    if (save_arg_vars[i] == 0)
      continue;
    for (reg = 0; reg < 32; reg++) {
      if (save_arg_vars[i] & (1 << reg)) {
        fprintf(fout, "  u32 %s;\n",
          saved_arg_name(buf1, sizeof(buf1), i, reg + 1));
        had_decl = 1;
      }
    }
  }

  if (regmask_ffca) {
    for (reg = 0; reg < 32; reg++) {
      if (regmask_ffca & (1 << reg)) {
        fprintf(fout, "  %s fs_%d;\n", float_type, reg + 1);
        had_decl = 1;
      }
    }
  }

  // declare push-pop temporaries
  if (regmask_pp) {
    for (reg = 0; reg < 8; reg++) {
      if (regmask_pp & (1 << reg)) {
        fprintf(fout, "  u32 pp_%s;\n", regs_r32[reg]);
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

  // do stack clear, if needed
  if (g_sct_func_attr & SCTFA_CLEAR_SF) {
    fprintf(fout, "  ");
    if (g_stack_clear_len != 0) {
      if (g_stack_clear_len <= 4) {
        for (i = 0; i < g_stack_clear_len; i++)
          fprintf(fout, "sf.d[%d] = ", g_stack_clear_start + i);
        fprintf(fout, "0;\n");
      }
      else {
        fprintf(fout, "memset(&sf[%d], 0, %d);\n",
          g_stack_clear_start, g_stack_clear_len * 4);
      }
    }
    else
      fprintf(fout, "memset(&sf, 0, sizeof(sf));\n");
  }

  if (g_func_pp->is_vararg) {
    if (g_func_pp->argc_stack == 0)
      ferr(ops, "vararg func without stack args?\n");
    fprintf(fout, "  va_start(ap, a%d);\n", g_func_pp->argc);
  }

  // output ops
  for (i = 0; i < opcnt; i++)
  {
    if (g_labels[i] != NULL) {
      fprintf(fout, "\n%s:\n", g_labels[i]);
      label_pending = 1;

      delayed_flag_op = NULL;
      last_arith_dst = NULL;
    }

    po = &ops[i];
    if (po->flags & OPF_RMD)
      continue;

    lock_handled = 0;
    no_output = 0;

    #define assert_operand_cnt(n_) \
      if (po->operand_cnt != n_) \
        ferr(po, "operand_cnt is %d/%d\n", po->operand_cnt, n_)

    // conditional/flag using op?
    if (po->flags & OPF_CC)
    {
      int is_delayed = 0;

      tmp_op = po->datap;

      // we go through all this trouble to avoid using parsed_flag_op,
      // which makes generated code much nicer
      if (delayed_flag_op != NULL)
      {
        out_cmp_test(buf1, sizeof(buf1), delayed_flag_op,
          po->pfo, po->pfo_inv);
        is_delayed = 1;
      }
      else if (last_arith_dst != NULL
        && (po->pfo == PFO_Z || po->pfo == PFO_S || po->pfo == PFO_P
           || (tmp_op && (tmp_op->op == OP_AND || tmp_op->op == OP_OR))
           ))
      {
        struct parsed_op *po_arith = (void *)((char *)last_arith_dst
          - offsetof(struct parsed_op, operand[0]));
        ferr_assert(po, &ops[po_arith - ops] == po_arith);
        out_src_opr_u32(buf3, sizeof(buf3), po_arith, last_arith_dst);
        out_test_for_cc(buf1, sizeof(buf1), po, po->pfo, po->pfo_inv,
          last_arith_dst->lmod, buf3);
        is_delayed = 1;
      }
      else if (tmp_op != NULL) {
        // use preprocessed flag calc results
        if (!(tmp_op->pfomask & (1 << po->pfo)))
          ferr(po, "not prepared for pfo %d\n", po->pfo);

        // note: pfo_inv was not yet applied
        snprintf(buf1, sizeof(buf1), "(%scond_%s)",
          po->pfo_inv ? "!" : "", parsed_flag_op_names[po->pfo]);
      }
      else {
        ferr(po, "all methods of finding comparison failed\n");
      }
 
      if (po->flags & OPF_JMP) {
        fprintf(fout, "  if %s", buf1);
      }
      else if (po->op == OP_RCL || po->op == OP_RCR
               || po->op == OP_ADC || po->op == OP_SBB)
      {
        if (is_delayed)
          fprintf(fout, "  cond_%s = %s;\n",
            parsed_flag_op_names[po->pfo], buf1);
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
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        default_cast_to(buf3, sizeof(buf3), &po->operand[0]);
        fprintf(fout, "  %s = %s;", buf1,
            out_src_opr(buf2, sizeof(buf2), po, &po->operand[1],
              buf3, 0));
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
          out_src_opr(buf2, sizeof(buf2), po, &po->operand[1],
            default_cast_to(buf3, sizeof(buf3), &po->operand[0]), 0));
        fprintf(fout, " %s = %stmp;",
          out_dst_opr(buf1, sizeof(buf1), po, &po->operand[1]),
          default_cast_to(buf3, sizeof(buf3), &po->operand[1]));
        snprintf(g_comment, sizeof(g_comment), "xchg");
        break;

      case OP_NOT:
        assert_operand_cnt(1);
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        fprintf(fout, "  %s = ~%s;", buf1, buf1);
        break;

      case OP_XLAT:
        assert_operand_cnt(2);
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]);
        fprintf(fout, "  %s = *(u8 *)(%s + %s);", buf1, buf2, buf1);
        strcpy(g_comment, "xlat");
        break;

      case OP_CDQ:
        assert_operand_cnt(2);
        fprintf(fout, "  %s = (s32)%s >> 31;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
            out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]));
        strcpy(g_comment, "cdq");
        break;

      case OP_BSWAP:
        assert_operand_cnt(1);
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        fprintf(fout, "  %s = __builtin_bswap32(%s);", buf1, buf1);
        break;

      case OP_LODS:
        if (po->flags & OPF_REP) {
          assert_operand_cnt(3);
          // hmh..
          ferr(po, "TODO\n");
        }
        else {
          assert_operand_cnt(2);
          fprintf(fout, "  %s = %sesi; esi %c= %d;",
            out_dst_opr(buf1, sizeof(buf1), po, &po->operand[1]),
            lmod_cast_u_ptr(po, po->operand[1].lmod),
            (po->flags & OPF_DF) ? '-' : '+',
            lmod_bytes(po, po->operand[1].lmod));
          strcpy(g_comment, "lods");
        }
        break;

      case OP_STOS:
        if (po->flags & OPF_REP) {
          assert_operand_cnt(3);
          fprintf(fout, "  for (; ecx != 0; ecx--, edi %c= %d)\n",
            (po->flags & OPF_DF) ? '-' : '+',
            lmod_bytes(po, po->operand[1].lmod));
          fprintf(fout, "    %sedi = eax;\n",
            lmod_cast_u_ptr(po, po->operand[1].lmod));
          fprintf(fout, "  barrier();");
          strcpy(g_comment, "^ rep stos");
        }
        else {
          assert_operand_cnt(2);
          fprintf(fout, "  %sedi = eax; edi %c= %d;",
            lmod_cast_u_ptr(po, po->operand[1].lmod),
            (po->flags & OPF_DF) ? '-' : '+',
            lmod_bytes(po, po->operand[1].lmod));
          strcpy(g_comment, "stos");
        }
        break;

      case OP_MOVS:
        j = lmod_bytes(po, po->operand[0].lmod);
        strcpy(buf1, lmod_cast_u_ptr(po, po->operand[0].lmod));
        l = (po->flags & OPF_DF) ? '-' : '+';
        if (po->flags & OPF_REP) {
          assert_operand_cnt(3);
          fprintf(fout,
            "  for (; ecx != 0; ecx--, edi %c= %d, esi %c= %d)\n",
            l, j, l, j);
          fprintf(fout,
            "    %sedi = %sesi;\n", buf1, buf1);
          // this can overwrite many variables
          fprintf(fout, "  barrier();");
          strcpy(g_comment, "^ rep movs");
        }
        else {
          assert_operand_cnt(2);
          fprintf(fout, "  %sedi = %sesi; edi %c= %d; esi %c= %d;",
            buf1, buf1, l, j, l, j);
          strcpy(g_comment, "movs");
        }
        break;

      case OP_CMPS:
        // repe ~ repeat while ZF=1
        j = lmod_bytes(po, po->operand[0].lmod);
        strcpy(buf1, lmod_cast_u_ptr(po, po->operand[0].lmod));
        l = (po->flags & OPF_DF) ? '-' : '+';
        if (po->flags & OPF_REP) {
          assert_operand_cnt(3);
          fprintf(fout,
            "  while (ecx != 0) {\n");
          if (pfomask & (1 << PFO_C)) {
            // ugh..
            fprintf(fout,
            "    cond_c = %sesi < %sedi;\n", buf1, buf1);
            pfomask &= ~(1 << PFO_C);
          }
          fprintf(fout,
            "    cond_z = (%sesi == %sedi); esi %c= %d, edi %c= %d;\n",
              buf1, buf1, l, j, l, j);
          fprintf(fout,
            "    ecx--;\n"
            "    if (cond_z %s 0) break;\n",
              (po->flags & OPF_REPZ) ? "==" : "!=");
          fprintf(fout,
            "  }");
          snprintf(g_comment, sizeof(g_comment), "rep%s cmps",
            (po->flags & OPF_REPZ) ? "e" : "ne");
        }
        else {
          assert_operand_cnt(2);
          fprintf(fout,
            "  cond_z = (%sesi == %sedi); esi %c= %d; edi %c= %d;",
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
        j = lmod_bytes(po, po->operand[1].lmod);
        l = (po->flags & OPF_DF) ? '-' : '+';
        if (po->flags & OPF_REP) {
          assert_operand_cnt(3);
          fprintf(fout,
            "  while (ecx != 0) {\n");
          fprintf(fout,
            "    cond_z = (%seax == %sedi); edi %c= %d;\n",
              lmod_cast_u(po, po->operand[1].lmod),
              lmod_cast_u_ptr(po, po->operand[1].lmod), l, j);
          fprintf(fout,
            "    ecx--;\n"
            "    if (cond_z %s 0) break;\n",
              (po->flags & OPF_REPZ) ? "==" : "!=");
          fprintf(fout,
            "  }");
          snprintf(g_comment, sizeof(g_comment), "rep%s scas",
            (po->flags & OPF_REPZ) ? "e" : "ne");
        }
        else {
          assert_operand_cnt(2);
          fprintf(fout, "  cond_z = (%seax == %sedi); edi %c= %d;",
              lmod_cast_u(po, po->operand[1].lmod),
              lmod_cast_u_ptr(po, po->operand[1].lmod), l, j);
          strcpy(g_comment, "scas");
        }
        pfomask &= ~(1 << PFO_Z);
        last_arith_dst = NULL;
        delayed_flag_op = NULL;
        break;

      case OP_RDTSC:
        fprintf(fout, "  tmp64 = ext_rdtsc();\n");
        fprintf(fout, "  edx = tmp64 >> 32;\n");
        fprintf(fout, "  eax = tmp64;");
        break;

      case OP_CPUID:
        fprintf(fout, "  ext_cpuid(&eax, &ebx, &ecx, &edx);");
        break;

      // arithmetic w/flags
      case OP_AND:
        if (po->operand[1].type == OPT_CONST && !po->operand[1].val)
          goto dualop_arith_const;
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        goto dualop_arith;

      case OP_OR:
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        if (po->operand[1].type == OPT_CONST) {
          j = lmod_bytes(po, po->operand[0].lmod);
          if (((1ull << j * 8) - 1) == po->operand[1].val)
            goto dualop_arith_const;
        }
        goto dualop_arith;

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

      dualop_arith_const:
        // and 0, or ~0 used instead mov
        assert_operand_cnt(2);
        fprintf(fout, "  %s = %s;",
          out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
          out_src_opr(buf2, sizeof(buf2), po, &po->operand[1],
           default_cast_to(buf3, sizeof(buf3), &po->operand[0]), 0));
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
        fprintf(fout, "  %s %s= %s", buf1, op_to_c(po),
            out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]));
        if (po->operand[1].type != OPT_CONST)
          fprintf(fout, " & 0x1f");
        fprintf(fout, ";");
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

      case OP_SHLD:
      case OP_SHRD:
        assert_operand_cnt(3);
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        l = lmod_bytes(po, po->operand[0].lmod) * 8;
        out_src_opr_u32(buf3, sizeof(buf3), po, &po->operand[2]);
        if (po->operand[2].type != OPT_CONST) {
          // no handling for "undefined" case, hopefully not needed
          snprintf(buf2, sizeof(buf2), "(%s & 0x1f)", buf3);
          strcpy(buf3, buf2);
        }
        out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]);
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        if (po->op == OP_SHLD) {
          fprintf(fout, "  %s <<= %s; %s |= %s >> (%d - %s);",
            buf1, buf3, buf1, buf2, l, buf3);
          strcpy(g_comment, "shld");
        }
        else {
          fprintf(fout, "  %s >>= %s; %s |= %s << (%d - %s);",
            buf1, buf3, buf1, buf2, l, buf3);
          strcpy(g_comment, "shrd");
        }
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
          int z = PFOB_O | PFOB_C | PFOB_S | (1 << PFO_L);
          for (j = 0; j <= PFO_LE; j++) {
            if (pfomask & (1 << j)) {
              fprintf(fout, "  cond_%s = %d;\n",
                parsed_flag_op_names[j], (1 << j) & z ? 0 : 1);
              pfomask &= ~(1 << j);
            }
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
          out_src_opr_u32(buf1, sizeof(buf1), po, &po->operand[0]);
          out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]);
          if (po->operand[0].lmod == OPLM_DWORD) {
            fprintf(fout, "  tmp64 = (u64)%s + %s;\n", buf1, buf2);
            fprintf(fout, "  cond_c = tmp64 >> 32;\n");
            fprintf(fout, "  %s = (u32)tmp64;",
              out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]));
            strcat(g_comment, " add64");
          }
          else {
            fprintf(fout, "  cond_c = ((u32)%s + %s) >> %d;\n",
              buf1, buf2, lmod_bytes(po, po->operand[0].lmod) * 8);
            fprintf(fout, "  %s += %s;",
              out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
              buf2);
          }
          pfomask &= ~(1 << PFO_C);
          output_std_flags(fout, po, &pfomask, buf1);
          last_arith_dst = &po->operand[0];
          delayed_flag_op = NULL;
          break;
        }
        if (pfomask & (1 << PFO_LE)) {
          out_cmp_for_cc(buf1, sizeof(buf1), po, PFO_LE, 0, 1);
          fprintf(fout, "  cond_%s = %s;\n",
            parsed_flag_op_names[PFO_LE], buf1);
          pfomask &= ~(1 << PFO_LE);
        }
        goto dualop_arith;

      case OP_SUB:
        assert_operand_cnt(2);
        propagate_lmod(po, &po->operand[0], &po->operand[1]);
        if (pfomask & ~((1 << PFO_Z) | (1 << PFO_S))) {
          for (j = 0; j <= PFO_LE; j++) {
            if (!(pfomask & (1 << j)))
              continue;
            if (j == PFO_Z || j == PFO_S)
              continue;

            out_cmp_for_cc(buf1, sizeof(buf1), po, j, 0, 0);
            fprintf(fout, "  cond_%s = %s;\n",
              parsed_flag_op_names[j], buf1);
            pfomask &= ~(1 << j);
          }
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

      case OP_BSF:
      case OP_BSR:
        // on SKL, if src is 0, dst is left unchanged
        assert_operand_cnt(2);
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[1]);
        output_std_flag_z(fout, po, &pfomask, buf2);
        if (po->op == OP_BSF)
          snprintf(buf3, sizeof(buf3), "__builtin_ffs(%s) - 1", buf2);
        else
          snprintf(buf3, sizeof(buf3), "31 - __builtin_clz(%s)", buf2);
        fprintf(fout, "  if (%s) %s = %s;", buf2, buf1, buf3);
        last_arith_dst = &po->operand[0];
        delayed_flag_op = NULL;
        strcat(g_comment, po->op == OP_BSF ? " bsf" : " bsr");
        break;

      case OP_DEC:
        if (pfomask & ~(PFOB_S | PFOB_S | PFOB_C)) {
          for (j = 0; j <= PFO_LE; j++) {
            if (!(pfomask & (1 << j)))
              continue;
            if (j == PFO_Z || j == PFO_S || j == PFO_C)
              continue;

            out_cmp_for_cc(buf1, sizeof(buf1), po, j, 0, 0);
            fprintf(fout, "  cond_%s = %s;\n",
              parsed_flag_op_names[j], buf1);
            pfomask &= ~(1 << j);
          }
        }
        // fallthrough

      case OP_INC:
        if (pfomask & (1 << PFO_C))
          // carry is unaffected by inc/dec.. wtf?
          ferr(po, "carry propagation needed\n");

        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        if (po->operand[0].type == OPT_REG) {
          ferr_assert(po, !(po->flags & OPF_LOCK));
          strcpy(buf2, po->op == OP_INC ? "++" : "--");
          fprintf(fout, "  %s%s;", buf1, buf2);
        }
        else if (po->flags & OPF_LOCK) {
          out_src_opr(buf2, sizeof(buf2), po, &po->operand[0], "", 1);
          fprintf(fout, "  __sync_fetch_and_%s((%s *)(%s), 1);",
            po->op == OP_INC ? "add" : "sub",
            lmod_type_u(po, po->operand[0].lmod), buf2);
          strcat(g_comment, " lock");
          lock_handled = 1;
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
        if (pfomask & PFOB_C) {
          fprintf(fout, "\n  cond_c = (%s != 0);", buf1);
          pfomask &= ~PFOB_C;
        }
        output_std_flags(fout, po, &pfomask, buf1);
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
        switch (po->operand[0].lmod) {
        case OPLM_DWORD:
          strcpy(buf1, po->op == OP_IMUL ? "(s64)(s32)" : "(u64)");
          fprintf(fout, "  tmp64 = %seax * %s%s;\n", buf1, buf1,
            out_src_opr_u32(buf2, sizeof(buf2), po, &po->operand[0]));
          fprintf(fout, "  edx = tmp64 >> 32;\n");
          fprintf(fout, "  eax = tmp64;");
          break;
        case OPLM_BYTE:
          strcpy(buf1, po->op == OP_IMUL ? "(s16)(s8)" : "(u16)(u8)");
          fprintf(fout, "  LOWORD(eax) = %seax * %s;", buf1,
            out_src_opr(buf2, sizeof(buf2), po, &po->operand[0],
              buf1, 0));
          break;
        default:
          ferr(po, "TODO: unhandled mul type\n");
          break;
        }
        last_arith_dst = NULL;
        delayed_flag_op = NULL;
        break;

      case OP_DIV:
      case OP_IDIV:
        assert_operand_cnt(1);
        out_src_opr_u32(buf1, sizeof(buf1), po, &po->operand[0]);
        strcpy(cast, lmod_cast(po, po->operand[0].lmod,
          po->op == OP_IDIV));
        switch (po->operand[0].lmod) {
        case OPLM_DWORD:
          if (po->flags & OPF_32BIT)
            snprintf(buf2, sizeof(buf2), "%seax", cast);
          else {
            fprintf(fout, "  tmp64 = ((u64)edx << 32) | eax;\n");
            snprintf(buf2, sizeof(buf2), "%stmp64",
              (po->op == OP_IDIV) ? "(s64)" : "");
          }
          if (po->operand[0].type == OPT_REG
            && po->operand[0].reg == xDX)
          {
            fprintf(fout, "  eax = %s / %s%s;\n", buf2, cast, buf1);
            fprintf(fout, "  edx = %s %% %s%s;", buf2, cast, buf1);
          }
          else {
            fprintf(fout, "  edx = %s %% %s%s;\n", buf2, cast, buf1);
            fprintf(fout, "  eax = %s / %s%s;", buf2, cast, buf1);
          }
          break;
        case OPLM_WORD:
          fprintf(fout, "  tmp = (edx << 16) | (eax & 0xffff);\n");
          snprintf(buf2, sizeof(buf2), "%stmp",
            (po->op == OP_IDIV) ? "(s32)" : "");
          if (po->operand[0].type == OPT_REG
            && po->operand[0].reg == xDX)
          {
            fprintf(fout, "  LOWORD(eax) = %s / %s%s;\n",
              buf2, cast, buf1);
            fprintf(fout, "  LOWORD(edx) = %s %% %s%s;",
              buf2, cast, buf1);
          }
          else {
            fprintf(fout, "  LOWORD(edx) = %s %% %s%s;\n",
              buf2, cast, buf1);
            fprintf(fout, "  LOWORD(eax) = %s / %s%s;",
              buf2, cast, buf1);
          }
          strcat(g_comment, " div16");
          break;
        default:
          ferr(po, "unhandled div lmod %d\n", po->operand[0].lmod);
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

      case OP_SCC:
        // SETcc - should already be handled
        break;

      // note: we reuse OP_Jcc for SETcc, only flags differ
      case OP_JCC:
        fprintf(fout, "\n    goto %s;", po->operand[0].name);
        break;

      case OP_JECXZ:
        fprintf(fout, "  if (ecx == 0)\n");
        fprintf(fout, "    goto %s;", po->operand[0].name);
        strcat(g_comment, " jecxz");
        break;

      case OP_LOOP:
        fprintf(fout, "  if (--ecx != 0)\n");
        fprintf(fout, "    goto %s;", po->operand[0].name);
        strcat(g_comment, " loop");
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
        pp = po->pp;
        my_assert_not(pp, NULL);

        strcpy(buf3, "  ");
        if (po->flags & OPF_CC) {
          // we treat conditional branch to another func
          // (yes such code exists..) as conditional tailcall
          strcat(buf3, "  ");
          fprintf(fout, " {\n");
        }

        if (pp->is_fptr && !pp->is_arg) {
          fprintf(fout, "%s%s = %s;\n", buf3, pp->name,
            out_src_opr(buf1, sizeof(buf1), po, &po->operand[0],
              "(void *)", 0));
        }
        if (pp->is_fptr && (pp->is_unresolved || pp->is_guessed)) {
          fprintf(fout, "%sunresolved_call(\"%s:%d\", %s);\n",
            buf3, asmfn, po->asmln, pp->name);
        }

        fprintf(fout, "%s", buf3);
        if (strstr(pp->ret_type.name, "int64")) {
          if (po->flags & OPF_TAIL)
            ferr(po, "int64 and tail?\n");
          fprintf(fout, "tmp64 = ");
        }
        else if (!IS(pp->ret_type.name, "void")) {
          if (po->flags & OPF_TAIL) {
            if (regmask_ret & mxAX) {
              fprintf(fout, "return ");
              if (g_func_pp->ret_type.is_ptr != pp->ret_type.is_ptr)
                fprintf(fout, "(%s)", g_func_pp->ret_type.name);
            }
            else if (regmask_ret & mxST0)
              ferr(po, "float tailcall\n");
          }
          else if (po->regmask_dst & mxAX) {
            fprintf(fout, "eax = ");
            if (pp->ret_type.is_ptr)
              fprintf(fout, "(u32)");
          }
          else if (po->regmask_dst & mxST0) {
            ferr_assert(po, po->flags & OPF_FPUSH);
            if (need_float_stack)
              fprintf(fout, "f_st[--f_stp & 7] = ");
            else
              fprintf(fout, "f_st0 = ");
          }
        }

        if (pp->name[0] == 0)
          ferr(po, "missing pp->name\n");
        fprintf(fout, "%s%s(", pp->name,
          pp->has_structarg ? "_sa" : "");

        if (po->flags & OPF_ATAIL) {
          int check_compat =
            g_func_pp->is_stdcall && g_func_pp->argc_stack > 0;
          check_compat |= pp->argc_stack > 0;
          if (check_compat
           && (pp->argc_stack != g_func_pp->argc_stack
               || pp->is_stdcall != g_func_pp->is_stdcall))
            ferr(po, "incompatible arg-reuse tailcall\n");
          if (g_func_pp->has_retreg)
            ferr(po, "TODO: retreg+tailcall\n");

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
              if (pp->arg[arg].type.is_retreg)
                fprintf(fout, "&%s", pp->arg[arg].reg);
              else if (IS(pp->arg[arg].reg, "ebp")
                    && g_bp_frame && !(po->flags & OPF_EBP_S))
              {
                // rare special case
                fprintf(fout, "%s(u32)&sf.b[sizeof(sf)]", cast);
                strcat(g_comment, " bp_ref");
              }
              else
                fprintf(fout, "%s%s", cast, pp->arg[arg].reg);
              continue;
            }

            // stack arg
            if (pp->arg[arg].push_ref_cnt == 0)
              ferr(po, "parsed_op missing for arg%d\n", arg);
            if (pp->arg[arg].push_ref_cnt > 1)
              ferr_assert(po, pp->arg[arg].is_saved);
            tmp_op = pp->arg[arg].push_refs[0];
            ferr_assert(po, tmp_op != NULL);

            if (tmp_op->flags & OPF_VAPUSH) {
              fprintf(fout, "ap");
            }
            else if (tmp_op->op == OP_FST) {
              fprintf(fout, "fs_%d", tmp_op->p_argnum);
              if (tmp_op->operand[0].lmod == OPLM_QWORD)
                arg++;
            }
            else if (pp->arg[arg].type.is_64bit) {
              ferr_assert(po, tmp_op->p_argpass == 0);
              ferr_assert(po, !pp->arg[arg].is_saved);
              ferr_assert(po, !pp->arg[arg].type.is_float);
              ferr_assert(po, cast[0] == 0);
              out_src_opr(buf1, sizeof(buf1),
                tmp_op, &tmp_op->operand[0], cast, 0);
              arg++;
              ferr_assert(po, pp->arg[arg].push_ref_cnt == 1);
              tmp_op = pp->arg[arg].push_refs[0];
              ferr_assert(po, tmp_op != NULL);
              out_src_opr(buf2, sizeof(buf2),
                tmp_op, &tmp_op->operand[0], cast, 0);
              fprintf(fout, "((u64)(%s) << 32) | (%s)",
                buf2, buf1);
            }
            else if (tmp_op->p_argpass != 0) {
              ferr_assert(po, !pp->arg[arg].type.is_float);
              fprintf(fout, "a%d", tmp_op->p_argpass);
            }
            else if (pp->arg[arg].is_saved) {
              ferr_assert(po, tmp_op->p_argnum > 0);
              ferr_assert(po, !pp->arg[arg].type.is_float);
              fprintf(fout, "%s%s", cast,
                saved_arg_name(buf1, sizeof(buf1),
                  tmp_op->p_arggrp, tmp_op->p_argnum));
            }
            else if (pp->arg[arg].type.is_float) {
              ferr_assert(po, !pp->arg[arg].type.is_64bit);
              fprintf(fout, "%s",
                out_src_opr_float(buf1, sizeof(buf1),
                  tmp_op, &tmp_op->operand[0], need_float_stack));
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
          fprintf(fout, "%sedx = tmp64 >> 32;\n", buf3);
          fprintf(fout, "%seax = tmp64;", buf3);
        }

        if (pp->is_unresolved) {
          snprintf(buf2, sizeof(buf2), " unresolved %dreg",
            pp->argc_reg);
          strcat(g_comment, buf2);
        }

        if (po->flags & OPF_TAIL) {
          ret = 0;
          if (i == opcnt - 1 || pp->is_noreturn)
            ret = 0;
          else if (IS(pp->ret_type.name, "void"))
            ret = 1;
          else if (!(regmask_ret & (1 << xAX)))
            ret = 1;
          // else already handled as 'return f()'

          if (ret) {
            fprintf(fout, "\n%sreturn;", buf3);
            strcat(g_comment, " ^ tailcall");
          }
          else
            strcat(g_comment, " tailcall");

          if ((regmask_ret & (1 << xAX))
            && IS(pp->ret_type.name, "void") && !pp->is_noreturn)
          {
            ferr(po, "int func -> void func tailcall?\n");
          }
        }
        if (pp->is_noreturn)
          strcat(g_comment, " noreturn");
        if ((po->flags & OPF_ATAIL) && pp->argc_stack > 0)
          strcat(g_comment, " argframe");
        if (po->flags & OPF_CC)
          strcat(g_comment, " cond");

        if (po->flags & OPF_CC)
          fprintf(fout, "\n  }");

        delayed_flag_op = NULL;
        last_arith_dst = NULL;
        break;

      case OP_RET:
      do_tail:
        if (g_func_pp->is_vararg)
          fprintf(fout, "  va_end(ap);\n");
        if (g_func_pp->has_retreg) {
          for (arg = 0; arg < g_func_pp->argc; arg++)
            if (g_func_pp->arg[arg].type.is_retreg)
              fprintf(fout, "  *r_%s = %s;\n",
                g_func_pp->arg[arg].reg, g_func_pp->arg[arg].reg);
        }
 
        if (regmask_ret & mxST0) {
          fprintf(fout, "  return %s;", float_st0);
        }
        else if (!(regmask_ret & mxAX)) {
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
        out_src_opr_u32(buf1, sizeof(buf1), po, &po->operand[0]);
        if (po->p_argnum != 0) {
          // special case - saved func arg
          fprintf(fout, "  %s = %s;",
            saved_arg_name(buf2, sizeof(buf2),
              po->p_arggrp, po->p_argnum), buf1);
          break;
        }
        else if (po->flags & OPF_RSAVE) {
          fprintf(fout, "  s_%s = %s;", buf1, buf1);
          break;
        }
        else if (po->flags & OPF_PPUSH) {
          tmp_op = po->datap;
          ferr_assert(po, tmp_op != NULL);
          out_dst_opr(buf2, sizeof(buf2), po, &tmp_op->operand[0]);
          fprintf(fout, "  pp_%s = %s;", buf2, buf1);
          break;
        }
        else if (g_func_pp->is_userstack) {
          fprintf(fout, "  *(--esp) = %s;", buf1);
          break;
        }
        if (!(g_ida_func_attr & IDAFA_NORETURN))
          ferr(po, "stray push encountered\n");
        no_output = 1;
        break;

      case OP_POP:
        out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]);
        if (po->flags & OPF_RSAVE) {
          fprintf(fout, "  %s = s_%s;", buf1, buf1);
          break;
        }
        else if (po->flags & OPF_PPUSH) {
          // push/pop graph / non-const
          ferr_assert(po, po->datap == NULL);
          fprintf(fout, "  %s = pp_%s;", buf1, buf1);
          break;
        }
        else if (po->datap != NULL) {
          // push/pop pair
          tmp_op = po->datap;
          fprintf(fout, "  %s = %s;", buf1,
            out_src_opr(buf2, sizeof(buf2),
              tmp_op, &tmp_op->operand[0],
              default_cast_to(buf3, sizeof(buf3), &po->operand[0]), 0));
          break;
        }
        else if (g_func_pp->is_userstack) {
          fprintf(fout, "  %s = *esp++;", buf1);
          break;
        }
        else
          ferr(po, "stray pop encountered\n");
        break;

      case OP_NOP:
        no_output = 1;
        break;

      // pseudo ops
      case OPP_ALLSHL:
      case OPP_ALLSHR:
        fprintf(fout, "  tmp64 = ((u64)edx << 32) | eax;\n");
        fprintf(fout, "  tmp64 = (s64)tmp64 %s LOBYTE(ecx);\n",
          po->op == OPP_ALLSHL ? "<<" : ">>");
        fprintf(fout, "  edx = tmp64 >> 32; eax = tmp64;");
        strcat(g_comment, po->op == OPP_ALLSHL
          ? " allshl" : " allshr");
        break;

      // x87
      case OP_FLD:
        if (need_float_stack) {
          out_src_opr_float(buf1, sizeof(buf1),
            po, &po->operand[0], 1);
          if (po->regmask_src & mxSTa) {
            fprintf(fout, "  f_st[(f_stp - 1) & 7] = %s; f_stp--;",
              buf1);
          }
          else
            fprintf(fout, "  f_st[--f_stp & 7] = %s;", buf1);
        }
        else {
          if (po->flags & OPF_FSHIFT)
            fprintf(fout, "  f_st1 = f_st0;");
          if (po->operand[0].type == OPT_REG
            && po->operand[0].reg == xST0)
          {
            strcat(g_comment, " fld st");
            break;
          }
          fprintf(fout, "  f_st0 = %s;",
            out_src_opr_float(buf1, sizeof(buf1),
              po, &po->operand[0], 0));
        }
        strcat(g_comment, " fld");
        break;

      case OP_FILD:
        out_src_opr(buf1, sizeof(buf1), po, &po->operand[0],
          lmod_cast(po, po->operand[0].lmod, 1), 0);
        snprintf(buf2, sizeof(buf2), "(%s)%s", float_type, buf1);
        if (need_float_stack) {
          fprintf(fout, "  f_st[--f_stp & 7] = %s;", buf2);
        }
        else {
          if (po->flags & OPF_FSHIFT)
            fprintf(fout, "  f_st1 = f_st0;");
          fprintf(fout, "  f_st0 = %s;", buf2);
        }
        strcat(g_comment, " fild");
        break;

      case OP_FLDc:
        if (need_float_stack)
          fprintf(fout, "  f_st[--f_stp & 7] = ");
        else {
          if (po->flags & OPF_FSHIFT)
            fprintf(fout, "  f_st1 = f_st0;");
          fprintf(fout, "  f_st0 = ");
        }
        switch (po->operand[0].val) {
        case X87_CONST_1:   fprintf(fout, "1.0;"); break;
        case X87_CONST_L2T: fprintf(fout, "3.321928094887362;"); break;
        case X87_CONST_L2E: fprintf(fout, "M_LOG2E;"); break;
        case X87_CONST_PI:  fprintf(fout, "M_PI;"); break;
        case X87_CONST_LG2: fprintf(fout, "0.301029995663981;"); break;
        case X87_CONST_LN2: fprintf(fout, "M_LN2;"); break;
        case X87_CONST_Z:   fprintf(fout, "0.0;"); break;
        default: ferr_assert(po, 0); break;
        }
        break;

      case OP_FST:
        dead_dst = 0;
        if (po->flags & OPF_FARG) {
          // store to stack as func arg
          fprintf(fout, "  fs_%d = %s;", po->p_argnum, float_st0);
        }
        else if (po->operand[0].type == OPT_REG
                 && po->operand[0].reg == xST0)
        {
          dead_dst = 1;
        }
        else if (float_opr_needs_helper(po, &po->operand[0])) {
          out_src_opr(buf1, sizeof(buf1), po, &po->operand[0], "", 1);
          fprintf(fout, "  %s_store(%s, %s);",
            po->operand[0].lmod == OPLM_QWORD ? "double" : "float",
            float_st0, buf1);
        }
        else {
          out_dst_opr_float(buf1, sizeof(buf1), po, &po->operand[0],
            need_float_stack);
          fprintf(fout, "  %s = %s;", buf1, float_st0);
        }
        if (po->flags & OPF_FSHIFT) {
          if (need_float_stack)
            fprintf(fout, "  f_stp++;");
          else
            fprintf(fout, "  f_st0 = f_st1;");
        }
        if (dead_dst && !(po->flags & OPF_FSHIFT))
          no_output = 1;
        else
          strcat(g_comment, " fst");
        break;

      case OP_FIST:
        fprintf(fout, "  %s = %s%s;",
          out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]),
            lmod_cast(po, po->operand[0].lmod, 1), float_st0);
        if (po->flags & OPF_FSHIFT) {
          if (need_float_stack)
            fprintf(fout, "  f_stp++;");
          else
            fprintf(fout, "  f_st0 = f_st1;");
        }
        strcat(g_comment, " fist");
        break;

      case OP_FABS:
        fprintf(fout, "  %s = fabs%s(%s);", float_st0,
          need_double ? "" : "f", float_st0);
        break;

      case OP_FADD:
      case OP_FDIV:
      case OP_FMUL:
      case OP_FSUB:
        out_dst_opr_float(buf1, sizeof(buf1), po, &po->operand[0],
          need_float_stack);
        out_src_opr_float(buf2, sizeof(buf2), po, &po->operand[1],
          need_float_stack);
        dead_dst = (po->flags & OPF_FPOP)
          && po->operand[0].type == OPT_REG
          && po->operand[0].reg == xST0;
        switch (po->op) {
        case OP_FADD: j = '+'; break;
        case OP_FDIV: j = '/'; break;
        case OP_FMUL: j = '*'; break;
        case OP_FSUB: j = '-'; break;
        default: j = 'x'; break;
        }
        if (need_float_stack) {
          if (!dead_dst)
            fprintf(fout, "  %s %c= %s;", buf1, j, buf2);
          if (po->flags & OPF_FSHIFT)
            fprintf(fout, "  f_stp++;");
        }
        else {
          if (po->flags & OPF_FSHIFT) {
            // note: assumes only 2 regs handled
            if (!dead_dst)
              fprintf(fout, "  f_st0 = f_st1 %c f_st0;", j);
            else
              fprintf(fout, "  f_st0 = f_st1;");
          }
          else if (!dead_dst)
            fprintf(fout, "  %s %c= %s;", buf1, j, buf2);
        }
        no_output = (dead_dst && !(po->flags & OPF_FSHIFT));
        break;

      case OP_FDIVR:
      case OP_FSUBR:
        out_dst_opr_float(buf1, sizeof(buf1), po, &po->operand[0],
          need_float_stack);
        out_src_opr_float(buf2, sizeof(buf2), po, &po->operand[1],
          need_float_stack);
        out_src_opr_float(buf3, sizeof(buf3), po, &po->operand[0],
          need_float_stack);
        dead_dst = (po->flags & OPF_FPOP)
          && po->operand[0].type == OPT_REG
          && po->operand[0].reg == xST0;
        j = po->op == OP_FDIVR ? '/' : '-';
        if (need_float_stack) {
          if (!dead_dst)
            fprintf(fout, "  %s = %s %c %s;", buf1, buf2, j, buf3);
          if (po->flags & OPF_FSHIFT)
            fprintf(fout, "  f_stp++;");
        }
        else {
          if (po->flags & OPF_FSHIFT) {
            if (!dead_dst)
              fprintf(fout, "  f_st0 = f_st0 %c f_st1;", j);
            else
              fprintf(fout, "  f_st0 = f_st1;");
          }
          else if (!dead_dst)
            fprintf(fout, "  %s = %s %c %s;", buf1, buf2, j, buf3);
        }
        no_output = (dead_dst && !(po->flags & OPF_FSHIFT));
        break;

      case OP_FIADD:
      case OP_FIDIV:
      case OP_FIMUL:
      case OP_FISUB:
        switch (po->op) {
        case OP_FIADD: j = '+'; break;
        case OP_FIDIV: j = '/'; break;
        case OP_FIMUL: j = '*'; break;
        case OP_FISUB: j = '-'; break;
        default: j = 'x'; break;
        }
        fprintf(fout, "  %s %c= (%s)%s;", float_st0,
          j, float_type,
          out_src_opr(buf1, sizeof(buf1), po, &po->operand[0],
            lmod_cast(po, po->operand[0].lmod, 1), 0));
        break;

      case OP_FIDIVR:
      case OP_FISUBR:
        fprintf(fout, "  %s = %s %c %s;", float_st0,
          out_src_opr_float(buf2, sizeof(buf2), po, &po->operand[1],
            need_float_stack),
          po->op == OP_FIDIVR ? '/' : '-', float_st0);
        break;

      case OP_FCOM: {
        int mask, z_check;
        ferr_assert(po, po->datap != NULL);
        mask = (long)po->datap & 0xffff;
        z_check = ((long)po->datap >> 16) & 1;
        out_src_opr_float(buf1, sizeof(buf1), po, &po->operand[0],
          need_float_stack);
        if (mask == 0x0100 || mask == 0x0500) { // C0 -> <
          fprintf(fout, "  f_sw = %s < %s ? 0x0100 : 0;",
            float_st0, buf1);
        }
        else if (mask == 0x4000 || mask == 0x4400) { // C3 -> =
          fprintf(fout, "  f_sw = %s == %s ? 0x4000 : 0;",
            float_st0, buf1);
        }
        else if (mask == 0x4100) { // C3, C0
          if (z_check) {
            fprintf(fout, "  f_sw = %s <= %s ? 0x4100 : 0;",
              float_st0, buf1);
            strcat(g_comment, " z_chk_det");
          }
          else {
            fprintf(fout, "  f_sw = %s == %s ? 0x4000 : "
                          "(%s < %s ? 0x0100 : 0);",
              float_st0, buf1, float_st0, buf1);
          }
        }
        else
          ferr(po, "unhandled sw mask: %x\n", mask);
        if (po->flags & OPF_FSHIFT) {
          if (need_float_stack) {
            if (po->flags & OPF_FPOPP)
              fprintf(fout, " f_stp += 2;");
            else
              fprintf(fout, " f_stp++;");
          }
          else {
            ferr_assert(po, !(po->flags & OPF_FPOPP));
            fprintf(fout, " f_st0 = f_st1;");
          }
        }
        break;
      }

      case OP_FNSTSW:
        fprintf(fout, "  %s = f_sw;",
          out_dst_opr(buf1, sizeof(buf1), po, &po->operand[0]));
        break;

      case OP_FCHS:
        fprintf(fout, "  %s = -%s;", float_st0, float_st0);
        break;

      case OP_FCOS:
        fprintf(fout, "  %s = cos%s(%s);", float_st0,
          need_double ? "" : "f", float_st0);
        break;

      case OP_FPATAN:
        if (need_float_stack) {
          fprintf(fout, "  %s = atan%s(%s / %s);", float_st1,
            need_double ? "" : "f", float_st1, float_st0);
          fprintf(fout, " f_stp++;");
        }
        else {
          fprintf(fout, "  f_st0 = atan%s(f_st1 / f_st0);",
            need_double ? "" : "f");
        }
        break;

      case OP_FYL2X:
        if (need_float_stack) {
          fprintf(fout, "  %s = %s * log2%s(%s);", float_st1,
            float_st1, need_double ? "" : "f", float_st0);
          fprintf(fout, " f_stp++;");
        }
        else {
          fprintf(fout, "  f_st0 = f_st1 * log2%s(f_st0);",
            need_double ? "" : "f");
        }
        strcat(g_comment, " fyl2x");
        break;

      case OP_FSIN:
        fprintf(fout, "  %s = sin%s(%s);", float_st0,
          need_double ? "" : "f", float_st0);
        break;

      case OP_FSQRT:
        fprintf(fout, "  %s = sqrt%s(%s);", float_st0,
          need_double ? "" : "f", float_st0);
        break;

      case OP_FXCH:
        dead_dst = po->operand[0].type == OPT_REG
          && po->operand[0].reg == xST0;
        if (!dead_dst) {
          out_src_opr_float(buf1, sizeof(buf1), po, &po->operand[0],
            need_float_stack);
          fprintf(fout, "  { %s t = %s; %s = %s; %s = t; }", float_type,
            float_st0, float_st0, buf1, buf1);
          strcat(g_comment, " fxch");
        }
        else
          no_output = 1;
        break;

      case OPP_FTOL:
        ferr_assert(po, po->flags & OPF_32BIT);
        fprintf(fout, "  eax = (s32)%s;", float_st0);
        if (po->flags & OPF_FSHIFT) {
          if (need_float_stack)
            fprintf(fout, " f_stp++;");
          else
            fprintf(fout, " f_st0 = f_st1;");
        }
        strcat(g_comment, " ftol");
        goto tail_check;

      case OPP_CIPOW:
        if (need_float_stack) {
          fprintf(fout, "  %s = pow%s(%s, %s);", float_st1,
            need_double ? "" : "f", float_st1, float_st0);
          fprintf(fout, " f_stp++;");
        }
        else {
          fprintf(fout, "  f_st0 = pow%s(f_st1, f_st0);",
            need_double ? "" : "f");
        }
        strcat(g_comment, " CIpow");
        goto tail_check;

      case OPP_ABORT:
        fprintf(fout, "  do_skip_code_abort();");
        break;

      // mmx
      case OP_EMMS:
        fprintf(fout, "  do_emms();");
        break;

      tail_check:
        if (po->flags & OPF_TAIL) {
          fprintf(fout, "\n");
          strcat(g_comment, " tail");
          goto do_tail;
        }
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

    if ((po->flags & OPF_LOCK) && !lock_handled)
      ferr(po, "unhandled lock\n");

    // see is delayed flag stuff is still valid
    if (delayed_flag_op != NULL && delayed_flag_op != po) {
      if (is_any_opr_modified(delayed_flag_op, po, 0))
        delayed_flag_op = NULL;
    }

    if (last_arith_dst != NULL && last_arith_dst != &po->operand[0]) {
      if (is_opr_modified(last_arith_dst, po))
        last_arith_dst = NULL;
    }

    if (!no_output)
      label_pending = 0;
  }

  if (g_stack_fsz && !g_stack_frame_used)
    fprintf(fout, "  (void)sf;\n");

  fprintf(fout, "}\n\n");

  gen_x_cleanup(opcnt);
}

static void gen_x_cleanup(int opcnt)
{
  int i;

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
      if (ops[i].pp)
        proto_release(ops[i].pp);
    }
  }
  g_func_pp = NULL;
}

struct func_proto_dep;

struct func_prototype {
  char name[NAMELEN];
  int id;
  int argc_stack;
  int regmask_dep;               // likely register args
  int regmask_use;               // used registers
  int has_ret:3;                 // -1, 0, 1: unresolved, no, yes
  unsigned int has_ret64:1;
  unsigned int dep_resolved:1;
  unsigned int is_stdcall:1;
  unsigned int eax_pass:1;       // returns without touching eax
  unsigned int ptr_taken:1;      // pointer taken of this func
  struct func_proto_dep *dep_func;
  int dep_func_cnt;
  const struct parsed_proto *pp; // seed pp, if any
};

struct func_proto_dep {
  char *name;
  struct func_prototype *proto;
  int regmask_live;             // .. at the time of call
  unsigned int ret_dep:1;       // return from this is caller's return
  unsigned int has_ret:1;       // found from eax use after return
  unsigned int has_ret64:1;
  unsigned int ptr_taken:1;     // pointer taken, not a call
};

static struct func_prototype *hg_fp;
static int hg_fp_cnt;

static struct scanned_var {
  char name[NAMELEN];
  enum opr_lenmod lmod;
  unsigned int is_seeded:1;
  unsigned int is_c_str:1;
  const struct parsed_proto *pp; // seed pp, if any
} *hg_vars;
static int hg_var_cnt;

static char **hg_refs;
static int hg_ref_cnt;

static void output_hdr_fp(FILE *fout, const struct func_prototype *fp,
  int count);

static struct func_prototype *hg_fp_add(const char *funcn)
{
  struct func_prototype *fp;

  if ((hg_fp_cnt & 0xff) == 0) {
    hg_fp = realloc(hg_fp, sizeof(hg_fp[0]) * (hg_fp_cnt + 0x100));
    my_assert_not(hg_fp, NULL);
    memset(hg_fp + hg_fp_cnt, 0, sizeof(hg_fp[0]) * 0x100);
  }

  fp = &hg_fp[hg_fp_cnt];
  snprintf(fp->name, sizeof(fp->name), "%s", funcn);
  fp->id = hg_fp_cnt;
  fp->argc_stack = -1;
  hg_fp_cnt++;

  return fp;
}

static struct func_proto_dep *hg_fp_find_dep(struct func_prototype *fp,
  const char *name)
{
  int i;

  for (i = 0; i < fp->dep_func_cnt; i++)
    if (IS(fp->dep_func[i].name, name))
      return &fp->dep_func[i];

  return NULL;
}

static void hg_fp_add_dep(struct func_prototype *fp, const char *name,
  unsigned int ptr_taken)
{
  struct func_proto_dep * dep;

  // is it a dupe?
  dep = hg_fp_find_dep(fp, name);
  if (dep != NULL && dep->ptr_taken == ptr_taken)
    return;

  if ((fp->dep_func_cnt & 0xff) == 0) {
    fp->dep_func = realloc(fp->dep_func,
      sizeof(fp->dep_func[0]) * (fp->dep_func_cnt + 0x100));
    my_assert_not(fp->dep_func, NULL);
    memset(&fp->dep_func[fp->dep_func_cnt], 0,
      sizeof(fp->dep_func[0]) * 0x100);
  }
  fp->dep_func[fp->dep_func_cnt].name = strdup(name);
  fp->dep_func[fp->dep_func_cnt].ptr_taken = ptr_taken;
  fp->dep_func_cnt++;
}

static int hg_fp_cmp_name(const void *p1_, const void *p2_)
{
  const struct func_prototype *p1 = p1_, *p2 = p2_;
  return strcmp(p1->name, p2->name);
}

#if 0
static int hg_fp_cmp_id(const void *p1_, const void *p2_)
{
  const struct func_prototype *p1 = p1_, *p2 = p2_;
  return p1->id - p2->id;
}
#endif

static void hg_ref_add(const char *name)
{
  if ((hg_ref_cnt & 0xff) == 0) {
    hg_refs = realloc(hg_refs, sizeof(hg_refs[0]) * (hg_ref_cnt + 0x100));
    my_assert_not(hg_refs, NULL);
    memset(hg_refs + hg_ref_cnt, 0, sizeof(hg_refs[0]) * 0x100);
  }

  hg_refs[hg_ref_cnt] = strdup(name);
  my_assert_not(hg_refs[hg_ref_cnt], NULL);
  hg_ref_cnt++;
}

// recursive register dep pass
// - track saved regs (part 2)
// - try to figure out arg-regs
// - calculate reg deps
static void gen_hdr_dep_pass(int i, int opcnt, unsigned char *cbits,
  struct func_prototype *fp, int regmask_save, int regmask_dst,
  int *regmask_dep, int *regmask_use, int *has_ret)
{
  struct func_proto_dep *dep;
  struct parsed_op *po;
  int from_caller = 0;
  int j, l;
  int reg;
  int ret;

  for (; i < opcnt; i++)
  {
    if (cbits[i >> 3] & (1 << (i & 7)))
      return;
    cbits[i >> 3] |= (1 << (i & 7));

    po = &ops[i];

    if ((po->flags & OPF_JMP) && po->op != OP_CALL) {
      if (po->flags & OPF_RMD)
        continue;

      if (po->btj != NULL) {
        // jumptable
        for (j = 0; j < po->btj->count; j++) {
          check_i(po, po->btj->d[j].bt_i);
          gen_hdr_dep_pass(po->btj->d[j].bt_i, opcnt, cbits, fp,
            regmask_save, regmask_dst, regmask_dep, regmask_use,
            has_ret);
        }
        return;
      }

      check_i(po, po->bt_i);
      if (po->flags & OPF_CJMP) {
        gen_hdr_dep_pass(po->bt_i, opcnt, cbits, fp,
          regmask_save, regmask_dst, regmask_dep, regmask_use,
          has_ret);
      }
      else {
        i = po->bt_i - 1;
      }
      continue;
    }

    if (po->flags & OPF_FARG)
      /* (just calculate register deps) */;
    else if (po->op == OP_PUSH && po->operand[0].type == OPT_REG)
    {
      reg = po->operand[0].reg;
      ferr_assert(po, reg >= 0);

      if (po->flags & OPF_RSAVE) {
        regmask_save |= 1 << reg;
        continue;
      }
      if (po->flags & OPF_DONE)
        continue;

      ret = scan_for_pop(i + 1, opcnt, i + opcnt * 2,
              reg, 0, 0, 0, 0);
      if (ret == 1) {
        regmask_save |= 1 << reg;
        po->flags |= OPF_RMD;
        scan_for_pop(i + 1, opcnt, i + opcnt * 3,
          reg, 0, 0, 0, OPF_RMD);
        continue;
      }
    }
    else if (po->flags & OPF_RMD)
      continue;
    else if (po->op == OP_CALL) {
      po->regmask_dst |= 1 << xAX;

      dep = hg_fp_find_dep(fp, po->operand[0].name);
      if (dep != NULL) {
        dep->regmask_live = regmask_save | regmask_dst;
        if (g_bp_frame && !(po->flags & OPF_EBP_S))
          dep->regmask_live |= 1 << xBP;
      }
      if ((po->flags & OPF_TAIL) && po->pp != NULL
          && po->pp->is_stdcall)
        fp->is_stdcall = 1;
    }
    else if (po->op == OP_RET) {
      if (po->operand_cnt > 0) {
        fp->is_stdcall = 1;
        if (fp->argc_stack >= 0
            && fp->argc_stack != po->operand[0].val / 4)
          ferr(po, "ret mismatch? (%d)\n", fp->argc_stack * 4);
        fp->argc_stack = po->operand[0].val / 4;
      }
    }

    if (!fp->eax_pass && (po->flags & OPF_TAIL)) {
      if (po->op == OP_CALL) {
        j = i;
        ret = 1;
      }
      else {
        j = -1;
        from_caller = 0;
        ret = resolve_origin_reg(i, xAX, i + opcnt * 4, &j, &from_caller);
      }

      if (ret != 1 && from_caller) {
        // unresolved eax - probably void func
        *has_ret = 0;
        fp->eax_pass = 1;
      }
      else {
        if (j >= 0 && ops[j].op == OP_CALL) {
          if (ops[j].pp != NULL && !ops[j].pp->is_unresolved) {
            int call_has_ret = !IS(ops[j].pp->ret_type.name, "void");
            if (ops[j].pp->is_noreturn) {
              // could be some fail path
              if (*has_ret == -1)
                *has_ret = call_has_ret;
            }
            else
              *has_ret = call_has_ret;
          }
          else {
            dep = hg_fp_find_dep(fp, ops[j].operand[0].name);
            if (dep != NULL)
              dep->ret_dep = 1;
            else
              *has_ret = 1;
          }
        }
        else
          *has_ret = 1;
      }
    }

    l = regmask_save | regmask_dst;
    if (g_bp_frame && !(po->flags & OPF_EBP_S))
      l |= 1 << xBP;

    l = po->regmask_src & ~l;
#if 0
    if (l)
      fnote(po, "dep |= %04x, dst %04x, save %04x (f %x)\n",
        l, regmask_dst, regmask_save, po->flags);
#endif
    *regmask_dep |= l;
    *regmask_use |= (po->regmask_src | po->regmask_dst)
                  & ~regmask_save;
    regmask_dst |= po->regmask_dst;

    if (po->flags & OPF_TAIL) {
      if (!(po->flags & OPF_CC)) // not cond. tailcall
        return;
    }
  }
}

static void gen_hdr(const char *funcn, int opcnt)
{
  unsigned char cbits[MAX_OPS / 8];
  const struct parsed_proto *pp_c;
  struct parsed_proto *pp;
  struct func_prototype *fp;
  struct func_proto_dep *dep;
  struct parsed_op *po;
  const char *tmpname;
  int regmask_dummy = 0;
  int regmask_dep;
  int regmask_use;
  int max_bp_offset = 0;
  int has_ret;
  int i, j, l;
  int ret;

  pp_c = proto_parse(g_fhdr, funcn, 1);
  if (pp_c != NULL)
    // already in seed, will add to hg_fp later
    return;

  fp = hg_fp_add(funcn);

  g_bp_frame = g_sp_frame = g_stack_fsz = 0;
  g_stack_frame_used = 0;
  g_seh_size = 0;

  // pass1:
  // - resolve all branches
  // - parse calls with labels
  resolve_branches_parse_calls(opcnt);

  // pass2:
  // - handle ebp/esp frame, remove ops related to it
  scan_prologue_epilogue(opcnt, NULL);

  // pass3:
  // - remove dead labels
  // - collect calls
  // - collect function ptr refs
  for (i = 0; i < opcnt; i++)
  {
    if (g_labels[i] != NULL && g_label_refs[i].i == -1) {
      free(g_labels[i]);
      g_labels[i] = NULL;
    }

    po = &ops[i];
    if (po->flags & (OPF_RMD|OPF_DONE))
      continue;

    if (po->op == OP_CALL) {
      if (po->operand[0].type == OPT_LABEL)
        hg_fp_add_dep(fp, opr_name(po, 0), 0);
      else if (po->pp != NULL)
        hg_fp_add_dep(fp, po->pp->name, 0);
    }
    else if (po->op == OP_MOV && po->operand[1].type == OPT_OFFSET) {
      tmpname = opr_name(po, 1);
      if (IS_START(tmpname, "p_") || IS_START(tmpname, "sub_"))
        hg_fp_add_dep(fp, tmpname, 1);
    }
    else if (po->op == OP_PUSH && po->operand[0].type == OPT_OFFSET) {
      tmpname = opr_name(po, 0);
      if (IS_START(tmpname, "p_") || IS_START(tmpname, "sub_"))
        hg_fp_add_dep(fp, tmpname, 1);
    }
  }

  // pass4:
  // - handle push <const>/pop pairs
  for (i = 0; i < opcnt; i++)
  {
    po = &ops[i];
    if (po->flags & (OPF_RMD|OPF_DONE))
      continue;

    if (po->op == OP_PUSH && po->operand[0].type == OPT_CONST)
      scan_for_pop_const(i, opcnt, i + opcnt * 13);
  }

  // pass5:
  // - process trivial calls
  for (i = 0; i < opcnt; i++)
  {
    po = &ops[i];
    if (po->flags & (OPF_RMD|OPF_DONE))
      continue;

    if (po->op == OP_CALL)
    {
      pp = process_call_early(i, opcnt, &j);
      if (pp != NULL) {
        if (!(po->flags & OPF_ATAIL))
          // since we know the args, try to collect them
          if (collect_call_args_early(i, opcnt, pp, NULL, NULL) != 0)
            pp = NULL;
      }

      if (pp != NULL) {
        if (j >= 0) {
          // commit esp adjust
          if (ops[j].op != OP_POP)
            patch_esp_adjust(&ops[j], pp->argc_stack * 4);
          else {
            for (l = 0; l < pp->argc_stack; l++)
              ops[j + l].flags |= OPF_DONE | OPF_RMD | OPF_NOREGS;
          }
        }

        po->flags |= OPF_DONE;
      }
    }
  }

  // pass6:
  // - track saved regs (simple)
  // - process calls
  for (i = 0; i < opcnt; i++)
  {
    po = &ops[i];
    if (po->flags & (OPF_RMD|OPF_DONE))
      continue;

    if (po->op == OP_PUSH && po->operand[0].type == OPT_REG
      && po->operand[0].reg != xCX)
    {
      ret = scan_for_pop_ret(i + 1, opcnt, po->operand[0].reg, 0);
      if (ret == 1) {
        // regmask_save |= 1 << po->operand[0].reg; // do it later
        po->flags |= OPF_RSAVE | OPF_RMD | OPF_DONE;
        scan_for_pop_ret(i + 1, opcnt, po->operand[0].reg, OPF_RMD);
      }
    }
    else if (po->op == OP_CALL)
    {
      pp = process_call(i, opcnt);

      if (!pp->is_unresolved && !(po->flags & OPF_ATAIL)) {
        // since we know the args, collect them
        ret = collect_call_args(po, i, opcnt, pp, &regmask_dummy,
                i + opcnt * 1);
      }
      if (!(po->flags & OPF_TAIL)
          && po->operand[0].type == OPT_LABEL)
      {
        dep = hg_fp_find_dep(fp, opr_name(po, 0));
        ferr_assert(po, dep != NULL);
        // treat al write as overwrite to avoid many false positives
        find_next_read_reg(i + 1, opcnt, xAX, OPLM_BYTE,
          i + opcnt * 25, &j);
        if (j != -1)
          dep->has_ret = 1;
        find_next_read_reg(i + 1, opcnt, xDX, OPLM_BYTE,
          i + opcnt * 26, &j);
        if (j != -1 && !IS_OP_INDIRECT_CALL(&ops[j]))
          dep->has_ret64 = 1;
      }
    }
  }

  // pass7
  memset(cbits, 0, (opcnt + 7) / 8);
  regmask_dep = regmask_use = 0;
  has_ret = -1;

  gen_hdr_dep_pass(0, opcnt, cbits, fp, 0, 0,
    &regmask_dep, &regmask_use, &has_ret);

  // find unreachable code - must be fixed in IDA
  for (i = 0; i < opcnt; i++)
  {
    if (cbits[i >> 3] & (1 << (i & 7)))
      continue;

    if (g_labels[i] == NULL && i > 0 && ops[i - 1].op == OP_CALL
      && ops[i - 1].pp != NULL && ops[i - 1].pp->is_osinc)
    {
      // the compiler sometimes still generates code after
      // noreturn OS functions
      break;
    }
    if (!(ops[i].flags & OPF_RMD)
        && ops[i].op != OP_NOP && ops[i].op != OPP_ABORT)
    {
      ferr(&ops[i], "unreachable code\n");
    }
  }

  for (i = 0; i < g_eqcnt; i++) {
    if (g_eqs[i].offset > max_bp_offset && g_eqs[i].offset < 4*32)
      max_bp_offset = g_eqs[i].offset;
  }

  if (fp->argc_stack < 0) {
    max_bp_offset = (max_bp_offset + 3) & ~3;
    fp->argc_stack = max_bp_offset / 4;
    if ((g_ida_func_attr & IDAFA_BP_FRAME) && fp->argc_stack > 0)
      fp->argc_stack--;
  }

  fp->regmask_dep = regmask_dep & ~((1 << xSP) | mxSTa);
  fp->regmask_use = regmask_use;
  fp->has_ret = has_ret;
#if 0
  printf("// has_ret %d, regmask_dep %x\n",
    fp->has_ret, fp->regmask_dep);
  output_hdr_fp(stdout, fp, 1);
  if (IS(funcn, "sub_10007F72")) exit(1);
#endif

  gen_x_cleanup(opcnt);
}

static void hg_fp_resolve_deps(struct func_prototype *fp)
{
  struct func_prototype fp_s;
  struct func_proto_dep *dep;
  int regmask_dep;
  int i;

  // this thing is recursive, so mark first..
  fp->dep_resolved = 1;

  for (i = 0; i < fp->dep_func_cnt; i++) {
    dep = &fp->dep_func[i];

    strcpy(fp_s.name, dep->name);
    dep->proto = bsearch(&fp_s, hg_fp, hg_fp_cnt,
      sizeof(hg_fp[0]), hg_fp_cmp_name);
    if (dep->proto != NULL) {
      if (dep->ptr_taken) {
        dep->proto->ptr_taken = 1;
        continue;
      }

      if (!dep->proto->dep_resolved)
        hg_fp_resolve_deps(dep->proto);

      regmask_dep = ~dep->regmask_live
                   & dep->proto->regmask_dep;
      fp->regmask_dep |= regmask_dep;
      // printf("dep %s %s |= %x\n", fp->name,
      //   fp->dep_func[i].name, regmask_dep);

      if (dep->has_ret && (dep->proto->regmask_use & mxAX))
        dep->proto->has_ret = 1;
      if (dep->has_ret64 && (dep->proto->regmask_use & mxDX))
        dep->proto->has_ret64 = 1;
      if (fp->has_ret == -1 && dep->ret_dep)
        fp->has_ret = dep->proto->has_ret;
    }
  }
}

// make all thiscall/edx arg functions referenced from .data fastcall
static void do_func_refs_from_data(void)
{
  struct func_prototype *fp, fp_s;
  int i;

  for (i = 0; i < hg_ref_cnt; i++) {
    strcpy(fp_s.name, hg_refs[i]);
    fp = bsearch(&fp_s, hg_fp, hg_fp_cnt,
      sizeof(hg_fp[0]), hg_fp_cmp_name);
    if (fp != NULL)
      fp->ptr_taken = 1;
  }
}

static void output_hdr_fp(FILE *fout, const struct func_prototype *fp,
  int count)
{
  const struct parsed_proto *pp;
  char *p, namebuf[NAMELEN];
  const char *name;
  int regmask_dep;
  int argc_normal;
  int j, arg;

  for (; count > 0; count--, fp++) {
    if (fp->has_ret == -1)
      fprintf(fout, "// ret unresolved\n");
#if 0
    fprintf(fout, "// dep:");
    for (j = 0; j < fp->dep_func_cnt; j++) {
      fprintf(fout, " %s/", fp->dep_func[j].name);
      if (fp->dep_func[j].proto != NULL)
        fprintf(fout, "%04x/%d", fp->dep_func[j].proto->regmask_dep,
          fp->dep_func[j].proto->has_ret);
    }
    fprintf(fout, "\n");
#endif

    p = strchr(fp->name, '@');
    if (p != NULL) {
      memcpy(namebuf, fp->name, p - fp->name);
      namebuf[p - fp->name] = 0;
      name = namebuf;
    }
    else
      name = fp->name;
    if (name[0] == '_')
      name++;

    pp = proto_parse(g_fhdr, name, 1);
    if (pp != NULL && pp->is_include)
      continue;

    if (fp->pp != NULL) {
      // part of seed, output later
      continue;
    }

    regmask_dep = fp->regmask_dep;
    argc_normal = fp->argc_stack;
    if (fp->ptr_taken && regmask_dep
        && (regmask_dep & ~(mxCX|mxDX)) == 0)
    {
      if ((regmask_dep & mxDX) || fp->argc_stack > 0)
        regmask_dep |= mxCX | mxDX;
    }

    fprintf(fout, "%-5s",
      fp->pp ? fp->pp->ret_type.name :
      fp->has_ret64 ? "__int64" :
      fp->has_ret ? "int" : "void");
    if (regmask_dep == mxCX && fp->is_stdcall && fp->argc_stack > 0) {
      fprintf(fout, "/*__thiscall*/  ");
      argc_normal++;
      regmask_dep = 0;
    }
    else if ((regmask_dep == (mxCX | mxDX)
              && (fp->is_stdcall || fp->argc_stack == 0))
      || (regmask_dep == mxCX && fp->argc_stack == 0))
    {
      fprintf(fout, "  __fastcall    ");
      if (!(regmask_dep & (1 << xDX)) && fp->argc_stack == 0)
        argc_normal = 1;
      else
        argc_normal += 2;
      regmask_dep = 0;
    }
    else if (regmask_dep && !fp->is_stdcall) {
      fprintf(fout, "/*__usercall*/  ");
    }
    else if (regmask_dep) {
      fprintf(fout, "/*__userpurge*/ ");
    }
    else if (fp->is_stdcall)
      fprintf(fout, "  __stdcall     ");
    else
      fprintf(fout, "  __cdecl       ");

    fprintf(fout, "%s(", name);

    arg = 0;
    for (j = 0; j < xSP; j++) {
      if (regmask_dep & (1 << j)) {
        arg++;
        if (arg != 1)
          fprintf(fout, ", ");
        if (fp->pp != NULL)
          fprintf(fout, "%s", fp->pp->arg[arg - 1].type.name);
        else
          fprintf(fout, "int");
        fprintf(fout, " a%d/*<%s>*/", arg, regs_r32[j]);
      }
    }

    for (j = 0; j < argc_normal; j++) {
      arg++;
      if (arg != 1)
        fprintf(fout, ", ");
      if (fp->pp != NULL) {
        fprintf(fout, "%s", fp->pp->arg[arg - 1].type.name);
        if (!fp->pp->arg[arg - 1].type.is_ptr)
          fprintf(fout, " ");
      }
      else
        fprintf(fout, "int ");
      fprintf(fout, "a%d", arg);
    }

    fprintf(fout, ");\n");
  }
}

static void output_hdr(FILE *fout)
{
  static const char *lmod_c_names[] = {
    [OPLM_UNSPEC] = "???",
    [OPLM_BYTE]  = "uint8_t",
    [OPLM_WORD]  = "uint16_t",
    [OPLM_DWORD] = "uint32_t",
    [OPLM_QWORD] = "uint64_t",
  };
  const struct scanned_var *var;
  struct func_prototype *fp;
  char line[256] = { 0, };
  char name[256];
  int i;

  // add stuff from headers
  for (i = 0; i < pp_cache_size; i++) {
    if (pp_cache[i].is_cinc && !pp_cache[i].is_stdcall)
      snprintf(name, sizeof(name), "_%s", pp_cache[i].name);
    else
      snprintf(name, sizeof(name), "%s", pp_cache[i].name);
    fp = hg_fp_add(name);
    fp->pp = &pp_cache[i];
    fp->argc_stack = fp->pp->argc_stack;
    fp->is_stdcall = fp->pp->is_stdcall;
    fp->regmask_dep = get_pp_arg_regmask_src(fp->pp);
    fp->has_ret = !IS(fp->pp->ret_type.name, "void");
  }

  // resolve deps
  qsort(hg_fp, hg_fp_cnt, sizeof(hg_fp[0]), hg_fp_cmp_name);
  for (i = 0; i < hg_fp_cnt; i++)
    hg_fp_resolve_deps(&hg_fp[i]);

  // adjust functions referenced from data segment
  do_func_refs_from_data();

  // final adjustments
  for (i = 0; i < hg_fp_cnt; i++) {
    if (hg_fp[i].eax_pass && (hg_fp[i].regmask_dep & mxAX))
      hg_fp[i].has_ret = 1;
  }

  // note: messes up .proto ptr, don't use
  //qsort(hg_fp, hg_fp_cnt, sizeof(hg_fp[0]), hg_fp_cmp_id);

  // output variables
  for (i = 0; i < hg_var_cnt; i++) {
    var = &hg_vars[i];

    if (var->pp != NULL)
      // part of seed
      continue;
    else if (var->is_c_str)
      fprintf(fout, "extern %-8s %s[];", "char", var->name);
    else
      fprintf(fout, "extern %-8s %s;",
        lmod_c_names[var->lmod], var->name);

    if (var->is_seeded)
      fprintf(fout, " // seeded");
    fprintf(fout, "\n");
  }

  fprintf(fout, "\n");

  // output function prototypes
  output_hdr_fp(fout, hg_fp, hg_fp_cnt);

  // seed passthrough
  fprintf(fout, "\n// - seed -\n");

  rewind(g_fhdr);
  while (fgets(line, sizeof(line), g_fhdr))
    fwrite(line, 1, strlen(line), fout);
}

// '=' needs special treatment
// also ' quote
static char *next_word_s(char *w, size_t wsize, char *s)
{
  size_t i;

  s = sskip(s);

  i = 0;
  if (*s == '\'' && s[1] != '\r' && s[1] != '\n') {
    w[0] = s[0];
    for (i = 1; i < wsize - 1; i++) {
      if (s[i] == 0) {
        printf("warning: missing closing quote: \"%s\"\n", s);
        break;
      }
      if (s[i] == '\'')
        break;
      w[i] = s[i];
    }
  }

  for (; i < wsize - 1; i++) {
    if (s[i] == 0 || my_isblank(s[i]) || (s[i] == '=' && i > 0))
      break;
    w[i] = s[i];
  }
  w[i] = 0;

  if (s[i] != 0 && !my_isblank(s[i]) && s[i] != '=')
    printf("warning: '%s' truncated\n", w);

  return s + i;
}

static int cmpstringp(const void *p1, const void *p2)
{
  return strcmp(*(char * const *)p1, *(char * const *)p2);
}

static int is_xref_needed(char *p, char **rlist, int rlist_len)
{
  char *p2;

  p = sskip(p);
  if (strstr(p, "..."))
    // unable to determine, assume needed
    return 1;

  if (*p == '.') // .text, .data, ...
    // ref from other data or non-function -> no
    return 0;

  p2 = strpbrk(p, "+:\r\n\x18");
  if (p2 != NULL)
    *p2 = 0;
  if (bsearch(&p, rlist, rlist_len, sizeof(rlist[0]), cmpstringp))
    // referenced from removed code
    return 0;

  return 1;
}

static int ida_xrefs_show_need(FILE *fasm, char *p,
  char **rlist, int rlist_len)
{
  int found_need = 0;
  char line[256];
  long pos;

  p = strrchr(p, ';');
  if (p != NULL && *p == ';') {
    if (IS_START(p + 2, "sctref"))
      return 1;
    if (IS_START(p + 2, "DATA XREF: ")) {
      p += 13;
      if (is_xref_needed(p, rlist, rlist_len))
        return 1;
    }
  }

  pos = ftell(fasm);
  while (1)
  {
    if (!my_fgets(line, sizeof(line), fasm))
      break;
    // non-first line is always indented
    if (!my_isblank(line[0]))
      break;

    // should be no content, just comment
    p = sskip(line);
    if (*p != ';')
      break;

    p = strrchr(p, ';');
    p += 2;

    if (IS_START(p, "sctref")) {
      found_need = 1;
      break;
    }

    // it's printed once, but no harm to check again
    if (IS_START(p, "DATA XREF: "))
      p += 11;

    if (is_xref_needed(p, rlist, rlist_len)) {
      found_need = 1;
      break;
    }
  }
  fseek(fasm, pos, SEEK_SET);
  return found_need;
}

static void scan_variables(FILE *fasm, char **rlist, int rlist_len)
{
  struct scanned_var *var;
  char line[256] = { 0, };
  char words[4][256];
  int no_identifier;
  char *p = NULL;
  int wordc;
  int l;

  while (!feof(fasm))
  {
    // skip to next data section
    while (my_fgets(line, sizeof(line), fasm))
    {
      asmln++;

      p = sskip(line);
      if (*p == 0 || *p == ';')
        continue;

      p = sskip(next_word_s(words[0], sizeof(words[0]), p));
      if (*p == 0 || *p == ';')
        continue;

      if (*p != 's' || !IS_START(p, "segment para public"))
        continue;

      break;
    }

    if (p == NULL || !IS_START(p, "segment para public"))
      break;
    p = sskip(p + 19);

    if (!IS_START(p, "'DATA'"))
      continue;

    // now process it
    while (my_fgets(line, sizeof(line), fasm))
    {
      asmln++;

      p = line;
      no_identifier = my_isblank(*p);

      p = sskip(p);
      if (*p == 0 || *p == ';')
        continue;

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
      if (wordc < 2)
        continue;

      if (no_identifier) {
        if (wordc >= 3 && IS(words[0], "dd") && IS(words[1], "offset"))
          hg_ref_add(words[2]);
        continue;
      }

      if (IS_START(words[0], "__IMPORT_DESCRIPTOR_")) {
        // when this starts, we don't need anything from this section
        break;
      }

      // check refs comment(s)
      if (!ida_xrefs_show_need(fasm, p, rlist, rlist_len))
        continue;

      if ((hg_var_cnt & 0xff) == 0) {
        hg_vars = realloc(hg_vars, sizeof(hg_vars[0])
                   * (hg_var_cnt + 0x100));
        my_assert_not(hg_vars, NULL);
        memset(hg_vars + hg_var_cnt, 0, sizeof(hg_vars[0]) * 0x100);
      }

      var = &hg_vars[hg_var_cnt++];
      snprintf(var->name, sizeof(var->name), "%s", words[0]);

      // maybe already in seed header?
      var->pp = proto_parse(g_fhdr, var->name, 1);
      if (var->pp != NULL) {
        if (var->pp->is_fptr) {
          var->lmod = OPLM_DWORD;
          //var->is_ptr = 1;
        }
        else if (var->pp->is_func)
          aerr("func?\n");
        else if (!guess_lmod_from_c_type(&var->lmod, &var->pp->type))
          aerr("unhandled C type '%s' for '%s'\n",
            var->pp->type.name, var->name);

        var->is_seeded = 1;
        continue;
      }

      if      (IS(words[1], "dd")) {
        var->lmod = OPLM_DWORD;
        if (wordc >= 4 && IS(words[2], "offset"))
          hg_ref_add(words[3]);
      }
      else if (IS(words[1], "dw"))
        var->lmod = OPLM_WORD;
      else if (IS(words[1], "db")) {
        var->lmod = OPLM_BYTE;
        if (wordc >= 3 && (l = strlen(words[2])) > 4) {
          if (words[2][0] == '\'' && IS(words[2] + l - 2, ",0"))
            var->is_c_str = 1;
        }
      }
      else if (IS(words[1], "dq"))
        var->lmod = OPLM_QWORD;
      //else if (IS(words[1], "dt"))
      else
        aerr("type '%s' not known\n", words[1]);
    }
  }

  rewind(fasm);
  asmln = 0;
}

static void set_label(int i, const char *name)
{
  const char *p;
  int len;

  len = strlen(name);
  p = strchr(name, ':');
  if (p != NULL)
    len = p - name;

  if (g_labels[i] != NULL && !IS_START(g_labels[i], "algn_"))
    aerr("dupe label '%s' vs '%s'?\n", name, g_labels[i]);
  g_labels[i] = realloc(g_labels[i], len + 1);
  my_assert_not(g_labels[i], NULL);
  memcpy(g_labels[i], name, len);
  g_labels[i][len] = 0;
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

static void scan_ahead_for_chunks(FILE *fasm)
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

  while (my_fgets(line, sizeof(line), fasm))
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
      else if (IS_START(p, "; sctend"))
        break;

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
  int skip_code = 0;
  int skip_code_end = 0;
  int skip_warned = 0;
  int eq_alloc;
  int verbose = 0;
  int multi_seg = 0;
  int end = 0;
  int arg_out;
  int arg;
  int pi = 0;
  int i, j;
  int ret, len;
  char *p, *p2;
  int wordc;

  for (arg = 1; arg < argc; arg++) {
    if (IS(argv[arg], "-v"))
      verbose = 1;
    else if (IS(argv[arg], "-rf"))
      g_allow_regfunc = 1;
    else if (IS(argv[arg], "-uc"))
      g_allow_user_icall = 1;
    else if (IS(argv[arg], "-wu"))
      g_nowarn_reguse = 1;
    else if (IS(argv[arg], "-m"))
      multi_seg = 1;
    else if (IS(argv[arg], "-hdr"))
      g_header_mode = g_quiet_pp = g_allow_regfunc = 1;
    else
      break;
  }

  if (argc < arg + 3) {
    printf("usage:\n%s [options] <.c> <.asm> <hdr.h> [rlist]*\n"
           "%s -hdr <out.h> <.asm> <seed.h> [rlist]*\n"
           "options:\n"
           "  -hdr - header generation mode\n"
           "  -rf  - allow unannotated indirect calls\n"
           "  -uc  - allow ind. calls/refs to __usercall\n"
           "  -m   - allow multiple .text sections\n"
           "  -wu  - don't warn about bad reg use\n"
           "[rlist] is a file with function names to skip,"
           " one per line\n",
      argv[0], argv[0]);
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
    int skip_func = 0;

    frlist = fopen(argv[arg], "r");
    my_assert_not(frlist, NULL);

    while (my_fgets(line, sizeof(line), frlist)) {
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

  if (g_header_mode)
    scan_variables(fasm, rlist, rlist_len);

  while (my_fgets(line, sizeof(line), fasm))
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
      else if (p[2] == 's' && IS_START(p, "; sctattr:"))
      {
        static const char *attrs[] = {
          "clear_sf",
          "clear_regmask",
          "rm_regmask",
          "nowarn",
          "argframe",
          "align_float",
        };

        // parse manual attribute-list comment
        g_sct_func_attr = 0;
        p = sskip(p + 10);

        for (; *p != 0; p = sskip(p)) {
          for (i = 0; i < ARRAY_SIZE(attrs); i++) {
            if (!strncmp(p, attrs[i], strlen(attrs[i]))) {
              g_sct_func_attr |= 1 << i;
              p += strlen(attrs[i]);
              break;
            }
          }
          if (*p == '=') {
            j = ret = 0;
            if (i == 0)
              // clear_sf=start,len (in dwords)
              ret = sscanf(p, "=%d,%d%n", &g_stack_clear_start,
                      &g_stack_clear_len, &j);
            else if (i == 1)
              // clear_regmask=<mask>
              ret = sscanf(p, "=%x%n", &g_regmask_init, &j) + 1;
            else if (i == 2)
              // rm_regmask=<mask>
              ret = sscanf(p, "=%x%n", &g_regmask_rm, &j) + 1;
            if (ret < 2) {
              anote("unparsed attr value: %s\n", p);
              break;
            }
            p += j;
          }
          else if (i == ARRAY_SIZE(attrs)) {
            anote("unparsed sct attr: %s\n", p);
            break;
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
            //anote("scan_ahead caused by '%s', addr %lx\n",
            //  g_func, addr);
            scan_ahead_for_chunks(fasm);
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

    if (skip_code_end) {
      skip_code_end = 0;
      skip_code = 0;
    }

    // allow asm patches in comments
    if (*p == ';') {
      // skip IDA's forced non-removable comment
      if (!IS_START(p, "; sct") && (p2 = strchr(p + 1, ';')))
        p = p2;
    }
    if (*p == ';' && IS_START(p, "; sct")) {
      if (IS_START(p, "; sctpatch:")) {
        p = sskip(p + 11);
        if (*p == 0 || *p == ';')
          continue;
        goto parse_words; // lame
      }
      else if (IS_START(p, "; sctend")) {
        end = 1;
        if (!pending_endp)
          break;
      }
      else if (g_skip_func)
        /* ignore remaining attrs */;
      else if (IS_START(p, "; sctproto:")) {
        sctproto = strdup(p + 11);
      }
      else if (IS_START(p, "; sctskip_start")) {
        if (in_func) {
          if (!skip_code) {
            ops[pi].op = OPP_ABORT;
            ops[pi].asmln = asmln;
            pi++;
          }
          skip_code = 1;
        }
      }
      else if (IS_START(p, "; sctskip_end")) {
        if (skip_code)
          skip_code_end = 1;
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
      if (in_func && !g_skip_func && !end && wordc >= 2
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
            pd->d[pd->count].u.val = parse_number(words[i], 0);
          pd->d[pd->count].bt_i = -1;
          pd->count++;
        }
        continue;
      }

      if (in_func && !g_skip_func) {
        if (g_header_mode)
          gen_hdr(g_func, pi);
        else
          gen_func(fout, g_fhdr, g_func, pi);
      }

      pending_endp = 0;
      in_func = 0;
      g_ida_func_attr = 0;
      g_sct_func_attr = 0;
      g_stack_clear_start = 0;
      g_stack_clear_len = 0;
      g_regmask_init = 0;
      g_regmask_rm = 0;
      skip_warned = 0;
      g_skip_func = 0;
      g_func[0] = 0;
      g_seh_found = 0;
      func_chunks_used = 0;
      func_chunk_i = -1;
      if (pi != 0) {
        memset(&ops, 0, pi * sizeof(ops[0]));
        clear_labels(pi);
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
      g_func_lmods = 0;
      pd = NULL;

      if (end)
        break;
      if (wordc == 0)
        continue;
    }

    if (IS(words[1], "proc")) {
      if (in_func)
        aerr("proc '%s' while in_func '%s'?\n",
          words[0], g_func);
      p = words[0];
      if (bsearch(&p, rlist, rlist_len, sizeof(rlist[0]), cmpstringp))
        g_skip_func = 1;
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
      if (skip_code)
        aerr("endp '%s' while skipping code\n", words[0]);

      if ((g_ida_func_attr & IDAFA_THUNK) && pi == 1
        && ops[0].op == OP_JMP && ops[0].operand[0].segment)
      {
        // import jump
        g_skip_func = 1;
      }

      if (!g_skip_func && func_chunks_used) {
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

    if (wordc == 2 && IS(words[1], "ends")) {
      if (!multi_seg) {
        end = 1;
        if (pending_endp)
          goto do_pending_endp;
        break;
      }

      // scan for next text segment
      while (my_fgets(line, sizeof(line), fasm)) {
        asmln++;
        p = sskip(line);
        if (*p == 0 || *p == ';')
          continue;

        if (strstr(p, "segment para public 'CODE' use32"))
          break;
      }

      continue;
    }

    p = strchr(words[0], ':');
    if (p != NULL) {
      set_label(pi, words[0]);
      continue;
    }

    if (!in_func || g_skip_func || skip_code) {
      if (!skip_warned && !g_skip_func && g_labels[pi] != NULL) {
        if (verbose)
          anote("skipping from '%s'\n", g_labels[pi]);
        skip_warned = 1;
      }
      free(g_labels[pi]);
      g_labels[pi] = NULL;
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
      else if (IS(words[2], "qword"))
        g_eqs[g_eqcnt].lmod = OPLM_QWORD;
      else
        aerr("bad lmod: '%s'\n", words[2]);

      g_eqs[g_eqcnt].offset = parse_number(words[4], 0);
      g_eqcnt++;
      continue;
    }

    if (pi >= ARRAY_SIZE(ops))
      aerr("too many ops\n");

    parse_op(&ops[pi], words, wordc);

    ops[pi].datap = sctproto;
    sctproto = NULL;
    pi++;
  }

  if (g_header_mode)
    output_hdr(fout);

  fclose(fout);
  fclose(fasm);
  fclose(g_fhdr);

  return 0;
}

// vim:ts=2:shiftwidth=2:expandtab
