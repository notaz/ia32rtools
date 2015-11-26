/*
 * ia32rtools
 * (C) notaz, 2013-2015
 *
 * This work is licensed under the terms of 3-clause BSD license.
 * See COPYING file in the top-level directory.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "my_assert.h"
#include "my_str.h"
#include "common.h"

#include "protoparse.h"

static const char *asmfn;
static int asmln;

static const struct parsed_proto *g_func_sym_pp;
static char g_comment[256];
static int g_warn_cnt;
static int g_cconv_novalidate;
static int g_arm_mode;

// note: must be in ascending order
enum dx_type {
  DXT_UNSPEC,
  DXT_BYTE,
  DXT_WORD,
  DXT_DWORD,
  DXT_QUAD,
  DXT_TEN,
};

#define anote(fmt, ...) \
	printf("%s:%d: note: " fmt, asmfn, asmln, ##__VA_ARGS__)
#define awarn(fmt, ...) do { \
	printf("%s:%d: warning: " fmt, asmfn, asmln, ##__VA_ARGS__); \
  if (++g_warn_cnt == 10) { \
    fcloseall(); \
	  exit(1); \
  } \
} while (0)
#define aerr(fmt, ...) do { \
	printf("%s:%d: error: " fmt, asmfn, asmln, ##__VA_ARGS__); \
  fcloseall(); \
	exit(1); \
} while (0)

#include "masm_tools.h"

static char *next_word_s(char *w, size_t wsize, char *s)
{
  int quote = 0;
	size_t i;

	s = sskip(s);

	for (i = 0; i < wsize - 1; i++) {
    if (s[i] == '\'')
      quote ^= 1;
		if (s[i] == 0 || (!quote && (my_isblank(s[i]) || s[i] == ',')))
			break;
		w[i] = s[i];
	}
	w[i] = 0;

	if (s[i] != 0 && !my_isblank(s[i]) && s[i] != ',')
		printf("warning: '%s' truncated\n", w);

	return s + i;
}

static void next_section(FILE *fasm, char *name)
{
  char words[2][256];
  char line[256];
  int wordc;
  char *p;

  name[0] = 0;

  while (my_fgets(line, sizeof(line), fasm))
  {
    wordc = 0;
    asmln++;

    p = sskip(line);
    if (*p == 0)
      continue;

    if (*p == ';')
      continue;

    for (wordc = 0; wordc < ARRAY_SIZE(words); wordc++) {
      p = sskip(next_word(words[wordc], sizeof(words[0]), p));
      if (*p == 0 || *p == ';') {
        wordc++;
        break;
      }
    }

    if (wordc < 2)
      continue;

    if (!IS(words[1], "segment"))
      continue;

    strcpy(name, words[0]);
    break;
  }
}

static enum dx_type parse_dx_directive(const char *name)
{
  if (IS(name, "dd"))
    return DXT_DWORD;
  if (IS(name, "dw"))
    return DXT_WORD;
  if (IS(name, "db"))
    return DXT_BYTE;
  if (IS(name, "dq"))
    return DXT_QUAD;
  if (IS(name, "dt"))
    return DXT_TEN;

  return DXT_UNSPEC;
}

static const char *type_name(enum dx_type type)
{
  switch (type) {
  case DXT_BYTE:
    return ".byte";
  case DXT_WORD:
    return ".hword";
  case DXT_DWORD:
    return ".long";
  case DXT_QUAD:
    return ".quad";
  case DXT_TEN:
    return ".tfloat";
  case DXT_UNSPEC:
    break;
  }
  return "<bad>";
}

static const char *type_name_float(enum dx_type type)
{
  switch (type) {
  case DXT_DWORD:
    return ".float";
  case DXT_QUAD:
    return ".double";
  case DXT_TEN:
    return ".tfloat";
  default:
    break;
  }
  return "<bad_float>";
}

static int type_size(enum dx_type type)
{
  switch (type) {
  case DXT_BYTE:
    return 1;
  case DXT_WORD:
    return 2;
  case DXT_DWORD:
    return 4;
  case DXT_QUAD:
    return 8;
  case DXT_TEN:
    return 10;
  case DXT_UNSPEC:
    break;
  }
  return -1;
}

static char *escape_string(char *s)
{
  char buf[256];
  char *t = buf;

  for (; *s != 0; s++) {
    if (*s == '"') {
      strcpy(t, "\\\"");
      t += strlen(t);
      continue;
    }
    if (*s == '\\') {
      strcpy(t, "\\\\");
      t += strlen(t);
      continue;
    }
    *t++ = *s;
  }
  *t++ = *s;
  if (t - buf > sizeof(buf))
    aerr("string is too long\n");
  return strcpy(s, buf);
}

static void sprint_pp_short(const struct parsed_proto *pp, char *buf,
  size_t buf_size)
{
  char *p = buf;
  size_t l;
  int i;

  if (pp->ret_type.is_ptr)
    *p++ = 'p';
  else if (IS(pp->ret_type.name, "void"))
    *p++ = 'v';
  else
    *p++ = 'i';
  *p++ = '(';
  l = 2;

  for (i = 0; i < pp->argc; i++) {
    if (pp->arg[i].reg != NULL)
      snprintf(buf + l, buf_size - l, "%s%s",
        i == 0 ? "" : ",", pp->arg[i].reg);
    else
      snprintf(buf + l, buf_size - l, "%sa%d",
        i == 0 ? "" : ",", i + 1);
    l = strlen(buf);
  }
  snprintf(buf + l, buf_size - l, ")");
}

static const struct parsed_proto *check_var(FILE *fhdr,
  const char *sym, const char *varname, int is_export)
{
  const struct parsed_proto *pp, *pp_sym;
  char fp_sym[256], fp_var[256], *p;
  int i;

  pp = proto_parse(fhdr, varname, 1);
  if (pp == NULL) {
    if (IS_START(varname, "sub_"))
      awarn("sub_ sym missing proto: '%s'\n", varname);
    return NULL;
  }

  if (is_export)
    return NULL;
  if (!pp->is_func && !pp->is_fptr)
    return NULL;

  pp_print(fp_var, sizeof(fp_var), pp);

  if (pp->argc_reg == 0)
    goto check_sym;
  if (pp->argc_reg == 1 && pp->argc_stack == 0
    && IS(pp->arg[0].reg, "ecx"))
  {
    goto check_sym;
  }
  if (!g_cconv_novalidate
    && (pp->argc_reg != 2
       || !IS(pp->arg[0].reg, "ecx")
       || !IS(pp->arg[1].reg, "edx")))
  {
    awarn("unhandled reg call: %s\n", fp_var);
  }

check_sym:
  // fptrs must use 32bit args, callsite might have no information and
  // lack a cast to smaller types, which results in incorrectly masked
  // args passed (callee may assume masked args, it does on ARM)
  for (i = 0; i < pp->argc; i++) {
    if (pp->arg[i].type.is_ptr)
      continue;
    p = pp->arg[i].type.name;
    if (strstr(p, "int8") || strstr(p, "int16")
      || strstr(p, "char") || strstr(p, "short"))
    {
      awarn("reference to %s with arg%d '%s'\n", pp->name, i + 1, p);
    }
  }

  sprint_pp_short(pp, g_comment, sizeof(g_comment));

  if (sym != NULL) {
    g_func_sym_pp = NULL;
    pp_sym = proto_parse(fhdr, sym, 1);
    if (pp_sym == NULL)
      return pp;
    if (!pp_sym->is_fptr)
      aerr("func ptr data, but label '%s' !is_fptr\n", pp_sym->name);
    g_func_sym_pp = pp_sym;
  }
  else {
    pp_sym = g_func_sym_pp;
    if (pp_sym == NULL)
      return pp;
  }

  if (!pp_compatible_func(pp_sym, pp)) {
    pp_print(fp_sym, sizeof(fp_sym), pp_sym);
    anote("entry: %s\n", fp_var);
    anote("label: %s\n", fp_sym);
    awarn("^ mismatch\n");
  }

  return pp;
}

static void output_decorated_pp(FILE *fout,
  const struct parsed_proto *pp)
{
  if (pp->name[0] != '_')
    fprintf(fout, pp->is_fastcall ? "@" : "_");
  fprintf(fout, "%s", pp->name);
  if (pp->is_stdcall && pp->argc > 0)
    fprintf(fout, "@%d", pp->argc * 4);
}

static int align_value(int src_val)
{
  if (src_val <= 0) {
    awarn("bad align: %d\n", src_val);
    src_val = 1;
  }
  if (!g_arm_mode)
    return src_val;

  return __builtin_ffs(src_val) - 1;
}

static int cmpstringp(const void *p1, const void *p2)
{
  return strcmp(*(char * const *)p1, *(char * const *)p2);
}

/* XXX: maybe move to external file? */
static const char *unwanted_syms[] = {
  "aRuntimeError",
  "aTlossError",
  "aSingError",
  "aDomainError",
  "aR6029ThisAppli",
  "aR6028UnableToI",
  "aR6027NotEnough",
  "aR6026NotEnough",
  "aR6025PureVirtu",
  "aR6024NotEnough",
  "aR6019UnableToO",
  "aR6018Unexpecte",
  "aR6017Unexpecte",
  "aR6016NotEnough",
  "aAbnormalProgra",
  "aR6009NotEnough",
  "aR6008NotEnough",
  "aR6002FloatingP",
  "aMicrosoftVisua",
  "aRuntimeErrorPr",
  "aThisApplicatio",
  "aMicrosoftFindF",
  "aMicrosoftOffic",
};

static int is_unwanted_sym(const char *sym)
{
  return bsearch(&sym, unwanted_syms, ARRAY_SIZE(unwanted_syms),
    sizeof(unwanted_syms[0]), cmpstringp) != NULL;
}

int main(int argc, char *argv[])
{
  FILE *fout, *fasm, *fhdr = NULL, *frlist;
  const struct parsed_proto *pp;
  int no_decorations = 0;
  int header_mode = 0;
  int maybe_func_table;
  int in_export_table;
  int rm_labels_lines;
  int is_zero_val;
  char comment_char = '#';
  char words[20][256];
  char word[256];
  char line[256];
  char last_sym[32];
  unsigned long val;
  unsigned long cnt;
  uint64_t val64;
  const char *sym;
  enum dx_type type;
  char **pub_syms;
  int pub_sym_cnt = 0;
  int pub_sym_alloc;
  char **rlist;
  int rlist_cnt = 0;
  int rlist_alloc;
  int is_ro = 0;
  int is_label;
  int is_bss;
  int wordc;
  int first;
  int arg_out;
  int arg = 1;
  int len;
  int w, i;
  char *p;
  char *p2;

  if (argc < 4) {
    // -nd: no symbol decorations
    printf("usage:\n%s [-nd] [-i] [-a] <.s> <.asm> <hdrf> [rlist]*\n"
           "%s -hdr <.h> <.asm>\n",
      argv[0], argv[0]);
    return 1;
  }

  for (arg = 1; arg < argc; arg++) {
    if (IS(argv[arg], "-nd"))
      no_decorations = 1;
    else if (IS(argv[arg], "-i"))
      g_cconv_novalidate = 1;
    else if (IS(argv[arg], "-a")) {
      comment_char = '@';
      g_arm_mode = 1;
    }
    else if (IS(argv[arg], "-hdr"))
      header_mode = 1;
    else
      break;
  }

  arg_out = arg++;

  asmfn = argv[arg++];
  fasm = fopen(asmfn, "r");
  my_assert_not(fasm, NULL);

  if (!header_mode) {
    hdrfn = argv[arg++];
    fhdr = fopen(hdrfn, "r");
    my_assert_not(fhdr, NULL);
  }

  fout = fopen(argv[arg_out], "w");
  my_assert_not(fout, NULL);

  pub_sym_alloc = 64;
  pub_syms = malloc(pub_sym_alloc * sizeof(pub_syms[0]));
  my_assert_not(pub_syms, NULL);

  rlist_alloc = 64;
  rlist = malloc(rlist_alloc * sizeof(rlist[0]));
  my_assert_not(rlist, NULL);

  for (; arg < argc; arg++) {
    frlist = fopen(argv[arg], "r");
    my_assert_not(frlist, NULL);

    while (my_fgets(line, sizeof(line), frlist)) {
      p = sskip(line);
      if (*p == 0 || *p == ';' || *p == '#')
        continue;

      p = next_word(words[0], sizeof(words[0]), p);
      if (words[0][0] == 0)
        continue;

      if (rlist_cnt >= rlist_alloc) {
        rlist_alloc = rlist_alloc * 2 + 64;
        rlist = realloc(rlist, rlist_alloc * sizeof(rlist[0]));
        my_assert_not(rlist, NULL);
      }
      rlist[rlist_cnt++] = strdup(words[0]);
    }

    fclose(frlist);
    frlist = NULL;
  }

  if (rlist_cnt > 0)
    qsort(rlist, rlist_cnt, sizeof(rlist[0]), cmpstringp);

  qsort(unwanted_syms, ARRAY_SIZE(unwanted_syms),
    sizeof(unwanted_syms[0]), cmpstringp);

  while (1) {
    last_sym[0] = 0;
    g_func_sym_pp = NULL;
    maybe_func_table = 0;
    in_export_table = 0;
    rm_labels_lines = 0;

    next_section(fasm, line);
    if (feof(fasm))
      break;
    if (IS(line + 1, "text"))
      continue;

    if (IS(line + 1, "rdata")) {
      is_ro = 1;
      if (!header_mode)
        fprintf(fout, "\n.section .rodata\n");
    }
    else if (IS(line + 1, "data")) {
      is_ro = 0;
      if (!header_mode)
        fprintf(fout, "\n.data\n");
    }
    else
      aerr("unhandled section: '%s'\n", line);

    if (!header_mode)
      fprintf(fout, ".align %d\n", align_value(4));

    while (my_fgets(line, sizeof(line), fasm))
    {
      is_zero_val = 0;
      sym = NULL;
      asmln++;

      p = sskip(line);
      if (*p == 0)
        continue;

      if (*p == ';') {
        if (IS_START(p, ";org") && sscanf(p + 5, "%Xh", &i) == 1) {
          // ;org is only seen at section start, so assume . addr 0
          i &= 0xfff;
          if (i != 0 && !header_mode)
            fprintf(fout, "\t\t  .skip 0x%x\n", i);
        }
        else if (IS_START(p, "; Export Address"))
          in_export_table = 1;
        else if (IS_START(p, "; Export"))
          in_export_table = 0;
        continue;
      }

      for (wordc = 0; wordc < ARRAY_SIZE(words); wordc++) {
        p = sskip(next_word_s(words[wordc], sizeof(words[0]), p));
        if (*p == 0 || *p == ';') {
          wordc++;
          break;
        }
        if (*p == ',') {
          p = sskip(p + 1);
        }
      }

      if (*p == ';') {
        p = sskip(p + 1);
        if (IS_START(p, "sctclrtype")) {
          maybe_func_table = 0;
          g_func_sym_pp = NULL;
        }
      }

      if (wordc == 2 && IS(words[1], "ends"))
        break;
      if (wordc <= 2 && IS(words[0], "end"))
        break;
      if (wordc < 2)
        aerr("unhandled: '%s'\n", words[0]);

      // don't cares
      if (IS(words[0], "assume"))
        continue;

      if (IS(words[0], "align")) {
        if (header_mode)
          continue;

        val = parse_number(words[1], 0);
        fprintf(fout, "\t\t  .align %d", align_value(val));
        goto fin;
      }

      if (IS(words[0], "public")) {
        // skip, sym should appear in header anyway
        continue;
      }

      w = 1;
      type = parse_dx_directive(words[0]);
      if (type == DXT_UNSPEC) {
        type = parse_dx_directive(words[1]);
        sym = words[0];
        w = 2;
      }
      if (type == DXT_UNSPEC)
        aerr("unhandled decl: '%s %s'\n", words[0], words[1]);

      if (sym != NULL)
      {
        if (header_mode) {
          int is_str = 0;

          fprintf(fout, "extern ");
          if (is_ro)
            fprintf(fout, "const ");

          switch (type) {
          case DXT_BYTE:
            for (i = w; i < wordc; i++)
              if (words[i][0] == '\'')
                is_str = 1;
            if (is_str)
              fprintf(fout, "char     %s[];\n", sym);
            else
              fprintf(fout, "uint8_t  %s;\n", sym);
            break;

          case DXT_WORD:
            fprintf(fout, "uint16_t %s;\n", sym);
            break;

          case DXT_DWORD:
            fprintf(fout, "uint32_t %s;\n", sym);
            break;

          default:
            fprintf(fout, "_UNKNOWN %s;\n", sym);
            break;
          }

          continue;
        }

        snprintf(last_sym, sizeof(last_sym), "%s", sym);
        maybe_func_table = type == DXT_DWORD;

        if (IS_START(sym, "__IMPORT_DESCRIPTOR_")) {
          rm_labels_lines = 5;
          maybe_func_table = 0;
        }

        pp = proto_parse(fhdr, sym, 1);
        if (pp != NULL) {
          g_func_sym_pp = NULL;

          // public/global name
          if (pub_sym_cnt >= pub_sym_alloc) {
            pub_sym_alloc *= 2;
            pub_syms = realloc(pub_syms, pub_sym_alloc * sizeof(pub_syms[0]));
            my_assert_not(pub_syms, NULL);
          }
          pub_syms[pub_sym_cnt++] = strdup(sym);
        }

        len = strlen(sym);
        fprintf(fout, "%s%s:", no_decorations ? "" : "_", sym);

        len += 2;
        if (len < 8)
          fprintf(fout, "\t");
        if (len < 16)
          fprintf(fout, "\t");
        if (len <= 16)
          fprintf(fout, "  ");
        else
          fprintf(fout, " ");
      }
      else {
        if (header_mode)
          continue;

        fprintf(fout, "\t\t  ");
      }

      // fill out some unwanted strings with zeroes..
      if (type == DXT_BYTE && words[w][0] == '\''
        && is_unwanted_sym(last_sym))
      {
        len = 0;
        for (; w < wordc; w++) {
          if (words[w][0] == '\'') {
            p = words[w] + 1;
            for (; *p && *p != '\''; p++)
              len++;
          }
          else {
            // assume encoded byte
            len++;
          }
        }
        fprintf(fout, ".skip %d", len);
        goto fin;
      }
      else if (type == DXT_BYTE
        && (words[w][0] == '\''
            || (w + 1 < wordc && words[w + 1][0] == '\'')))
      {
        // string; use asciz for most common case
        if (w == wordc - 2 && IS(words[w + 1], "0")) {
          fprintf(fout, ".asciz \"");
          wordc--;
        }
        else
          fprintf(fout, ".ascii \"");

        for (; w < wordc; w++) {
          if (words[w][0] == '\'') {
            p = words[w] + 1;
            p2 = strchr(p, '\'');
            if (p2 == NULL)
              aerr("unterminated string? '%s'\n", p);
            memcpy(word, p, p2 - p);
            word[p2 - p] = 0;
            fprintf(fout, "%s", escape_string(word));
          }
          else {
            val = parse_number(words[w], 0);
            if (val & ~0xff)
              aerr("bad string trailing byte?\n");
            // unfortunately \xHH is unusable - gas interprets
            // things like \x27b as 0x7b, so have to use octal here
            fprintf(fout, "\\%03lo", val);
          }
        }
        fprintf(fout, "\"");
        goto fin;
      }

      if (w == wordc - 2) {
        if (IS_START(words[w + 1], "dup(")) {
          cnt = parse_number(words[w], 0);
          p = words[w + 1] + 4;
          p2 = strchr(p, ')');
          if (p2 == NULL)
            aerr("bad dup?\n");
          memmove(word, p, p2 - p);
          word[p2 - p] = 0;

          val = 0;
          if (!IS(word, "?"))
            val = parse_number(word, 0);

          fprintf(fout, ".fill 0x%02lx,%d,0x%02lx",
            cnt, type_size(type), val);
          goto fin;
        }
      }

      if (type == DXT_DWORD && words[w][0] == '\''
        && words[w][5] == '\'' && strlen(words[w]) == 6)
      {
        if (w != wordc - 1)
          aerr("TODO\n");

        p = words[w];
        val = (p[1] << 24) | (p[2] << 16) | (p[3] << 8) | p[4];
        fprintf(fout, ".long 0x%lx", val);
        snprintf(g_comment, sizeof(g_comment), "%s", words[w]);
        goto fin;
      }

      if (type >= DXT_DWORD && strchr(words[w], '.'))
      {
        if (w != wordc - 1)
          aerr("TODO\n");

        if (g_arm_mode && type == DXT_TEN) {
          fprintf(fout, ".fill 10");
          snprintf(g_comment, sizeof(g_comment), "%s %s",
            type_name_float(type), words[w]);
        }
        else
          fprintf(fout, "%s %s", type_name_float(type), words[w]);
        goto fin;
      }

      first = 1;
      fprintf(fout, "%s ", type_name(type));
      for (; w < wordc; w++)
      {
        if (!first)
          fprintf(fout, ", ");

        is_label = is_bss = 0;
        if (w <= wordc - 2 && IS(words[w], "offset")) {
          is_label = 1;
          w++;
        }
        else if (IS(words[w], "?")) {
          is_bss = 1;
        }
        else if (type == DXT_DWORD
                 && !('0' <= words[w][0] && words[w][0] <= '9'))
        {
          // assume label
          is_label = 1;
        }

        if (is_bss) {
          fprintf(fout, "0");
        }
        else if (is_label) {
          p = words[w];
          if (IS_START(p, "loc_") || IS_START(p, "__imp")
             || strchr(p, '?') || strchr(p, '@')
             || rm_labels_lines > 0
             || bsearch(&p, rlist, rlist_cnt, sizeof(rlist[0]),
                  cmpstringp))
          {
            fprintf(fout, "0");
            snprintf(g_comment, sizeof(g_comment), "%s", p);
          }
          else {
            const char *f_sym = maybe_func_table ? last_sym : NULL;

            pp = check_var(fhdr, f_sym, p, in_export_table);
            if (pp == NULL) {
              fprintf(fout, "%s%s",
                (no_decorations || p[0] == '_') ? "" : "_", p);
            }
            else {
              if (no_decorations)
                fprintf(fout, "%s", pp->name);
              else
                output_decorated_pp(fout, pp);
            }
          }
        }
        else {
          val64 = parse_number(words[w], 1);
          if (val64 < 10)
            fprintf(fout, "%d", (int)val64);
          else
            fprintf(fout, "0x%" PRIx64, val64);

          is_zero_val = val64 == 0;
        }

        first = 0;
      }

fin:
      if (!is_zero_val)
        maybe_func_table = 0;

      if (rm_labels_lines > 0)
        rm_labels_lines--;

      if (g_comment[0] != 0) {
        fprintf(fout, "\t\t%c %s", comment_char, g_comment);
        g_comment[0] = 0;
      }
      fprintf(fout, "\n");
    }
  }

  fprintf(fout, "\n");

  // dump public syms
  for (i = 0; i < pub_sym_cnt; i++)
    fprintf(fout, ".global %s%s\n",
      no_decorations ? "" : "_", pub_syms[i]);

  fclose(fout);
  fclose(fasm);
  if (fhdr != NULL)
    fclose(fhdr);

  return 0;
}

// vim:ts=2:shiftwidth=2:expandtab
