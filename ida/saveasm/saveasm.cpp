/*
 * ia32rtools
 * (C) notaz, 2013-2015
 *
 * This work is licensed under the terms of 3-clause BSD license.
 * See COPYING file in the top-level directory.
 */

#define NO_OBSOLETE_FUNCS
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#include <name.hpp>
#include <frame.hpp>
#include <struct.hpp>
#include <offset.hpp>
#include <auto.hpp>
#include <intel.hpp>

#define IS_START(w, y) !strncmp(w, y, strlen(y))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

static char **name_cache;
static size_t name_cache_size;

// non-local branch targets
static ea_t *nonlocal_bt;
static int nonlocal_bt_alloc;
static int nonlocal_bt_cnt;

//--------------------------------------------------------------------------
static int idaapi init(void)
{
  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
static void idaapi term(void)
{
  size_t i;

  if (nonlocal_bt != NULL) {
    free(nonlocal_bt);
    nonlocal_bt = NULL;
  }
  nonlocal_bt_alloc = 0;

  if (name_cache != NULL) {
    for (i = 0; i < name_cache_size; i++)
      free(name_cache[i]);
    free(name_cache);
    name_cache = NULL;
  }
  name_cache_size = 0;
}

//--------------------------------------------------------------------------

static const char *reserved_names[] = {
  "name",
  "type",
  "offset",
  "aam",
  "aas",
  "text",
  "size",
  "c",
  "align",
  "addr",
};

static int is_name_reserved(const char *name)
{
  int i;
  for (i = 0; i < ARRAY_SIZE(reserved_names); i++)
    if (strcasecmp(name, reserved_names[i]) == 0)
      return 1;

  return 0;
}

/* these tend to cause linker conflicts */
static const char *useless_names[] = {
  "target", "addend", "lpMem", "Locale", "lpfn",
  "CodePage", "uNumber", "Caption", "Default", "SubKey",
  "ValueName", "OutputString", "LibFileName", "AppName",
  "Buffer", "ClassName", "dwProcessId", "FileName",
  "aExp", "aLog10", "aDelete", "aFont",
  "lpCriticalSection", "CriticalSection", "lpAddress",
  "lpBuffer", "lpClassName", "lpName",
  "hHeap", "hEvent", "hHandle", "hObject",
  "hLibModule", "hInstance",
};

static int is_name_useless(const char *name)
{
  int i;
  for (i = 0; i < ARRAY_SIZE(useless_names); i++)
    if (strcasecmp(name, useless_names[i]) == 0)
      return 1;

  return 0;
}

static int nonlocal_bt_cmp(const void *p1, const void *p2)
{
  const ea_t *e1 = (const ea_t *)p1, *e2 = (const ea_t *)p2;
  return *e1 - *e2;
}

static void nonlocal_add(ea_t ea)
{
  if (nonlocal_bt_cnt >= nonlocal_bt_alloc) {
    nonlocal_bt_alloc += nonlocal_bt_alloc * 2 + 64;
    nonlocal_bt = (ea_t *)realloc(nonlocal_bt,
      nonlocal_bt_alloc * sizeof(nonlocal_bt[0]));
    if (nonlocal_bt == NULL) {
      msg("OOM\n");
      return;
    }
  }
  nonlocal_bt[nonlocal_bt_cnt++] = ea;
}

// is instruction a (un)conditional jump (not call)?
static int is_insn_jmp(uint16 itype)
{
  return itype == NN_jmp || (NN_ja <= itype && itype <= NN_jz);
}

static void do_def_line(char *buf, size_t buf_size, const char *line,
  ea_t ea, func_t *func)
{
  char func_name[256] = "<nf>";
  int is_libfunc = 0;
  int global_label;
  ea_t *ea_ret;
  int i, len;
  char *p;

  tag_remove(line, buf, buf_size); // remove color codes
  len = strlen(buf);
  if (len < 9) {
    buf[0] = 0;
    return;
  }
  memmove(buf, buf + 9, len - 9 + 1); // rm address

  p = buf;
  while (*p && *p != ' ' && *p != ':')
    p++;
  if (*p == ':') {
    ea_ret = (ea_t *)bsearch(&ea, nonlocal_bt, nonlocal_bt_cnt,
      sizeof(nonlocal_bt[0]), nonlocal_bt_cmp);
    global_label = (ea_ret != NULL);
    if (!global_label) {
      if (func != NULL) {
        get_func_name(ea, func_name, sizeof(func_name));
        is_libfunc = func->flags & FUNC_LIB;
      }
      for (i = 0; i < get_item_size(ea); i++) {
        xrefblk_t xb;
        if (xb.first_to(ea + i, XREF_DATA)) {
          if (!is_libfunc && xb.type == dr_O)
            msg("%x: offset xref in %s\n", ea, func_name);
          global_label = 1;
        }
      }
    }
    if (global_label) {
      if (p[1] != ' ')
        msg("no trailing blank in '%s'\n", buf);
      else
        p[1] = ':';
    }
  }
}

static int name_cache_cmp(const void *p1, const void *p2)
{
  // masm ignores case, so do we
  return stricmp(*(char * const *)p1, *(char * const *)p2);
}

static void rebuild_name_cache(void)
{
  size_t i, newsize;
  void *tmp;

  // build a sorted name cache
  newsize = get_nlist_size();
  if (newsize > name_cache_size) {
    tmp = realloc(name_cache, newsize * sizeof(name_cache[0]));
    if (tmp == NULL) {
      msg("OOM for name cache\n");
      return;
    }
    name_cache = (char **)tmp;
  }
  for (i = 0; i < name_cache_size; i++)
    free(name_cache[i]);
  for (i = 0; i < newsize; i++)
    name_cache[i] = strdup(get_nlist_name(i));

  name_cache_size = newsize;
  qsort(name_cache, name_cache_size, sizeof(name_cache[0]),
    name_cache_cmp);
}

static void my_rename(ea_t ea, char *name)
{
  char buf[256];
  char *p, **pp;
  int n = 0;

  qsnprintf(buf, sizeof(buf), "%s", name);
  do {
    p = buf;
    pp = (char **)bsearch(&p, name_cache, name_cache_size,
        sizeof(name_cache[0]), name_cache_cmp);
    if (pp == NULL)
      break;

    qsnprintf(buf, sizeof(buf), "%s_g%d", name, n);
    n++;
  }
  while (n < 100);

  if (n == 100)
    msg("rename failure? '%s'\n", name);

  do_name_anyway(ea, buf);
  rebuild_name_cache();
}

static void make_align(ea_t ea)
{
  ea_t tmp_ea;
  int n;

  tmp_ea = next_head(ea, inf.maxEA);
  if ((tmp_ea & 0x03) == 0) {
    n = calc_max_align(tmp_ea);
    if (n > 4) // masm doesn't like more..
      n = 4;
    msg("%x: align %d\n", ea, 1 << n);
    do_unknown(ea, DOUNK_SIMPLE);
    doAlign(ea, tmp_ea - ea, n);
  }
}

static void idaapi run(int /*arg*/)
{
  // isEnabled(ea) // address belongs to disassembly
  // ea_t ea = get_screen_ea();
  // extern foo;
  // foo = DecodeInstruction(ScreenEA());
  FILE *fout = NULL;
  int fout_line = 0;
  char buf[MAXSTR];
  char buf2[MAXSTR];
  const char *name;
  const char *cp;
  struc_t *frame;
  func_t *func;
  ea_t ui_ea_block = 0, ea_size;
  ea_t tmp_ea, target_ea;
  ea_t ea;
  flags_t ea_flags;
  uval_t idx;
  int i, o, m, n;
  int ret;
  char **pp;
  char *p;

  nonlocal_bt_cnt = 0;

  // get rid of structs, masm doesn't understand them
  idx = get_first_struc_idx();
  while (idx != BADNODE) {
    tid_t tid = get_struc_by_idx(idx);
    struc_t *struc = get_struc(tid);
    get_struc_name(tid, buf, sizeof(buf));
    msg("removing struct '%s'\n", buf);
    //del_struc_members(struc, 0, get_max_offset(struc));
    del_struc(struc);

    idx = get_first_struc_idx();
  }

  rebuild_name_cache();

  // 1st pass: walk through all funcs
  ea = inf.minEA;
  func = get_func(ea);
  while (func != NULL)
  {
    func_tail_iterator_t fti(func);
    if (!fti.main()) {
      msg("%x: func_tail_iterator_t main failed\n", ea);
      return;
    }
    const area_t &f_area = fti.chunk();
    ea = f_area.startEA;

    // rename global syms which conflict with frame member names
    frame = get_frame(func);
    if (frame != NULL)
    {
      for (m = 0; m < (int)frame->memqty; m++)
      {
        ret = get_member_name(frame->members[m].id, buf, sizeof(buf));
        if (ret <= 0) {
          msg("%x: member has no name?\n", ea);
          return;
        }
        if (buf[0] == ' ') // what's this?
          continue;
        if (IS_START(buf, "arg_") || IS_START(buf, "var_"))
          continue;

        // check for dupe names
        int m1, dupe = 0;
        for (m1 = 0; m1 < m; m1++) {
          get_member_name(frame->members[m1].id, buf2, sizeof(buf2));
          if (stricmp(buf, buf2) == 0)
            dupe = 1;
        }

        if (is_name_reserved(buf) || dupe) {
          msg("%x: renaming '%s'\n", ea, buf);
          qstrncat(buf, "_", sizeof(buf));
          ret = set_member_name(frame, frame->members[m].soff, buf);
          if (!ret) {
            msg("%x: renaming failed\n", ea);
            return;
          }
        }

        p = buf;
        pp = (char **)bsearch(&p, name_cache, name_cache_size,
              sizeof(name_cache[0]), name_cache_cmp);
        if (pp == NULL)
          continue;

        tmp_ea = get_name_ea(BADADDR, *pp);
        msg("%x: renaming '%s' because of '%s' at %x\n",
          tmp_ea, *pp, buf, ea);
        my_rename(tmp_ea, *pp);
      }
    }

    // detect tailcalls to next func with 'jmp $+5' (offset 0)
    if (f_area.endEA - f_area.startEA >= 5
      && decode_insn(f_area.endEA - 5) && cmd.itype == NN_jmp
      && cmd.Operands[0].type == o_near
      && cmd.Operands[0].addr == f_area.endEA
      && get_name(BADADDR, f_area.endEA, buf, sizeof(buf))
      && get_cmt(f_area.endEA - 5, false, buf2, sizeof(buf2)) <= 0)
    {
      qsnprintf(buf2, sizeof(buf2), "sctpatch: jmp %s", buf);
      set_cmt(f_area.endEA - 5, buf2, false);
    }

    func = get_next_func(ea);
  }

  // 2nd pass over whole .text and .(ro)data segments
  for (ea = inf.minEA; ea != BADADDR; ea = next_head(ea, inf.maxEA))
  {
    segment_t *seg = getseg(ea);
    if (!seg)
      break;
    if (seg->type == SEG_XTRN)
      continue;
    if (seg->type != SEG_CODE && seg->type != SEG_DATA)
      break;

    ea_flags = get_flags_novalue(ea);
    func = get_func(ea);
    if (isCode(ea_flags))
    {
      if (!decode_insn(ea)) {
        msg("%x: decode_insn() failed\n", ea);
        continue;
      }

      // masm doesn't understand IDA's float/xmm types
      if (cmd.itype == NN_fld || cmd.itype == NN_fst
        || cmd.itype == NN_movapd || cmd.itype == NN_movlpd)
      {
        for (o = 0; o < UA_MAXOP; o++) {
          if (cmd.Operands[o].type == o_void)
            break;

          if (cmd.Operands[o].type == o_mem) {
            tmp_ea = cmd.Operands[o].addr;
            flags_t tmp_flg = get_flags_novalue(tmp_ea);
            buf[0] = 0;
            if (isDouble(tmp_flg))
            {
              get_name(ea, tmp_ea, buf, sizeof(buf));
              msg("%x: converting dbl %x '%s'\n", ea, tmp_ea, buf);
              doQwrd(tmp_ea, 8);
            }
            if (isOwrd(tmp_flg) || isYwrd(tmp_flg) || isTbyt(tmp_flg))
            {
              get_name(ea, tmp_ea, buf, sizeof(buf));
              msg("%x: undefining lrg %x '%s'\n", ea, tmp_ea, buf);
              do_unknown(tmp_ea, DOUNK_EXPAND);
            }
          }
        }
      }
      else if (cmd.itype == NN_lea) {
        // detect code alignment
        if (cmd.Operands[0].reg == cmd.Operands[1].reg
          && cmd.Operands[1].type == o_displ
          && cmd.Operands[1].addr == 0)
        {
          // lea eax, [eax+0]
          make_align(ea);
        }
        else if (!isDefArg1(ea_flags)
          && cmd.Operands[1].type == o_mem // why o_mem?
          && cmd.Operands[1].dtyp == dt_dword)
        {
          if (inf.minEA <= cmd.Operands[1].addr
            && cmd.Operands[1].addr < inf.maxEA)
          {
            // lea to segments, like ds:58D6A8h[edx*8]
            msg("%x: lea offset to %x\n", ea, cmd.Operands[1].addr);
            op_offset(ea, 1, REF_OFF32);
          }
          else
          {
            // ds:0[eax*8] -> [eax*8+0]
            msg("%x: dropping ds: for %x\n", ea, cmd.Operands[1].addr);
            op_hex(ea, 1);
          }
        }
      }
      else if (cmd.itype == NN_mov && cmd.segpref == 0x1e // 2e?
        && cmd.Operands[0].type == o_reg
        && cmd.Operands[1].type == o_reg
        && cmd.Operands[0].dtyp == cmd.Operands[1].dtyp
        && cmd.Operands[0].reg == cmd.Operands[1].reg)
      {
        // db 2Eh; mov eax, eax
        make_align(ea);
      }

      // find non-local branches
      if (is_insn_jmp(cmd.itype) && cmd.Operands[0].type == o_near)
      {
        target_ea = cmd.Operands[0].addr;
        if (func == NULL)
          nonlocal_add(target_ea);
        else {
          ret = get_func_chunknum(func, target_ea);
          if (ret != 0) {
            // a jump to another func or chunk
            // check if it lands on func start
            if (!isFunc(get_flags_novalue(target_ea)))
              nonlocal_add(target_ea);
          }
        }
      }
    }
    else { // not code
      int do_undef = 0;
      ea_size = get_item_size(ea);

      if (func == NULL && isOff0(ea_flags)) {
        for (tmp_ea = 0; tmp_ea < ea_size; tmp_ea += 4)
          nonlocal_add(get_long(ea + tmp_ea));
      }

      // IDA vs masm float/mmx/xmm type incompatibility
      if (isDouble(ea_flags))
      {
        msg("%x: converting double\n", ea);
        doQwrd(ea, 8);
      }
      else if (isTbyt(ea_flags) || isPackReal(ea_flags))
      {
        do_undef = 1;
      }
      else if (isOwrd(ea_flags)) {
        buf[0] = 0;
        get_name(BADADDR, ea, buf, sizeof(buf));
        if (IS_START(buf, "xmm"))
          do_undef = 1;
      }
      // masm doesn't understand IDA's unicode
      else if (isASCII(ea_flags) && ea_size >= 4
        && (get_long(ea) & 0xff00ff00) == 0) // lame..
      {
        do_undef = 1;
      }
      // masm doesn't understand large aligns
      else if (isAlign(ea_flags) && ea_size >= 0x10)
      {
        msg("%x: undefining align %d\n", ea, ea_size);
        do_unknown(ea, DOUNK_EXPAND);
      }

      if (do_undef) {
        buf[0] = 0;
        get_name(BADADDR, ea, buf, sizeof(buf));
        msg("%x: undefining '%s'\n", ea, buf);
        do_unknown(ea, DOUNK_EXPAND);
      }
    }
  }

  // check namelist for reserved names and
  // matching names with different case (masm ignores case)
  n = get_nlist_size();
  for (i = 0; i < n; i++) {
    int need_rename = 0;

    ea = get_nlist_ea(i);
    ea_flags = get_flags_novalue(ea);
    name = get_nlist_name(i);
    if (name == NULL) {
      msg("%x: null name?\n", ea);
      continue;
    }

    qsnprintf(buf, sizeof(buf), "%s", name);

    // for short names, give them a postfix to solve link dupe problem
    if (!isCode(ea_flags) && strlen(name) <= 4) {
      qsnprintf(buf, sizeof(buf), "%s_%06X", name, ea);
      need_rename = 1;
    }
    else {
      qsnprintf(buf2, sizeof(buf2), "%s", name);
      if ((p = strchr(buf2, '_')))
        *p = 0;
      if (is_name_useless(buf2)) {
        msg("%x: removing name '%s'\n", ea, name);
        ret = set_name(ea, "", SN_AUTO);
        if (ret) {
          n = get_nlist_size();
          i--;
          continue;
        }
      }
    }

    need_rename |= is_name_reserved(name);
    if (!need_rename) {
      p = buf;
      pp = (char **)bsearch(&p, name_cache, name_cache_size,
              sizeof(name_cache[0]), name_cache_cmp);
      if (pp != NULL) {
        if (pp > name_cache && stricmp(pp[-1], pp[0]) == 0)
          need_rename = 1;
        else if (pp < name_cache + name_cache_size - 1
          && stricmp(pp[0], pp[1]) == 0)
        {
          need_rename = 1;
        }
      }
    }

    // rename vars with '?@' (funcs are ok)
    int change_qat = 0;
    if (!isCode(ea_flags)) {
      if (IS_START(name, "__imp_"))
        need_rename = 0; /* some import */
      else if (name[0] == '?' && strstr(name, "@@"))
        need_rename = 0; /* c++ import */
      else if (strchr(name, '?'))
        change_qat = 1;
      else if ((cp = strchr(name, '@'))) {
        char *endp = NULL;
        strtol(cp + 1, &endp, 10);
        if (endp == NULL || *endp != 0)
          change_qat = 1;
      }
    }

    if (need_rename || change_qat) {
      msg("%x: renaming name '%s'\n", ea, name);

      if (change_qat) {
        for (p = buf; *p != 0; p++) {
          if (*p == '?' || *p == '@') {
            qsnprintf(buf2, sizeof(buf2), "%02x", (unsigned char)*p);
            memmove(p + 1, p, strlen(p) + 1);
            memcpy(p, buf2, 2);
          }
        }
      }

      my_rename(ea, buf);
    }
  }

  if (nonlocal_bt_cnt > 1) {
    qsort(nonlocal_bt, nonlocal_bt_cnt,
      sizeof(nonlocal_bt[0]), nonlocal_bt_cmp);
  }

  char *fname = askfile_c(1, NULL, "Save asm file");
  if (fname == NULL)
    return;
  fout = qfopen(fname, "w");
  if (fout == NULL) {
    msg("couldn't open '%s'\n", fname);
    return;
  }

  show_wait_box("Saving..");

  // deal with the beginning
  ea = inf.minEA;
  int flags = 0; // calc_default_idaplace_flags();
  linearray_t ln(&flags);
  idaplace_t pl;
  pl.ea = ea;
  pl.lnnum = 0;
  ln.set_place(&pl);
  n = ln.get_linecnt();
  for (i = 0; i < n - 1; i++) {
    do_def_line(buf, sizeof(buf), ln.down(), ea, NULL);
    if (strstr(buf, "include"))
      continue;

    fout_line++;
    qfprintf(fout, "%s\n", buf);
    p = strstr(buf, ".mmx");
    if (p != NULL) {
      memcpy(p, ".xmm", 4);
      fout_line++;
      qfprintf(fout, "%s\n", buf);
      continue;
    }
    p = strstr(buf, ".model");
    if (p != NULL) {
      qstrncpy(p, "include imports.inc", sizeof(buf) - (p - buf));
      fout_line++;
      qfprintf(fout, "\n%s\n", buf);
      i++;
      break;
    }
  }
  pl.lnnum = i;

  for (;;)
  {
    int drop_large = 0, do_rva = 0, set_scale = 0, jmp_near = 0;
    int word_imm = 0, dword_imm = 0, do_pushf = 0, do_nops = 0;

    if ((ea >> 14) != ui_ea_block) {
      ui_ea_block = ea >> 14;
      showAddr(ea);
      if (wasBreak())
        break;
    }

    func = get_func(ea);

    segment_t *seg = getseg(ea);
    if (!seg || (seg->type != SEG_CODE && seg->type != SEG_DATA))
      goto pass;

    ea_flags = get_flags_novalue(ea);
    if (isCode(ea_flags))
    {
      if (!decode_insn(ea))
        goto pass;

      if (is_insn_jmp(cmd.itype) && cmd.Operands[0].type == o_near
        && cmd.Operands[0].dtyp == dt_dword)
      {
        jmp_near = 1;
      }
      else if ((cmd.itype == NN_pushf || cmd.itype == NN_popf)
        && natop())
      {
        do_pushf = 1;
      }

      for (o = 0; o < UA_MAXOP; o++) {
        const op_t &opr = cmd.Operands[o];
        if (opr.type == o_void)
          break;

        // correct?
        if (opr.type == o_mem && opr.specval_shorts.high == 0x21)
          drop_large = 1;
        if (opr.hasSIB && x86_scale(opr) == 0
          && x86_index(opr) != INDEX_NONE)
        {
          set_scale = 1;
        }
        // annoying alignment variant..
        if (opr.type == o_imm && opr.dtyp == dt_dword
          && (opr.value < 0x80 || opr.value > 0xffffff80)
          && cmd.size >= opr.offb + 4)
        {
          if (get_long(ea + opr.offb) == opr.value)
            dword_imm = 1;
        }
        else if (opr.type == o_imm && opr.dtyp == dt_word
          && (opr.value < 0x80 || opr.value > 0xff80)
          && cmd.size >= opr.offb + 2)
        {
          if (get_word(ea + opr.offb) == (ushort)opr.value)
            word_imm = 1;
        }
        else if (opr.type == o_displ && opr.addr == 0
          && opr.offb != 0 && opr.hasSIB && opr.sib == 0x24)
        {
          // uses [esp+0] with 0 encoded into op
          do_nops++;
        }
      }
    }
    else { // not code
      if (isOff0(ea_flags))
        do_rva = 1;
    }

pass:
    n = ln.get_linecnt();
    for (i = pl.lnnum; i < n; i++) {
      do_def_line(buf, sizeof(buf), ln.down(), ea, func);

      char *fw;
      for (fw = buf; *fw != 0 && *fw == ' '; )
        fw++;

      // patches..
      if (drop_large) {
        p = strstr(fw, "large ");
        if (p != NULL)
          memmove(p, p + 6, strlen(p + 6) + 1);
      }
      while (do_rva) {
        p = strstr(fw, " rva ");
        if (p == NULL)
          break;
        memmove(p + 4 + 3, p + 4, strlen(p + 4) + 1);
        memcpy(p + 1, "offset", 6);
      }
      if (set_scale) {
        p = strchr(fw, '[');
        if (p != NULL)
          p = strchr(p, '+');
        if (p != NULL && p[1] == 'e') {
          p += 4;
          // scale is 1, must specify it explicitly so that
          // masm chooses the right scaled reg
          memmove(p + 2, p, strlen(p) + 1);
          memcpy(p, "*1", 2);
        }
      }
      else if (jmp_near) {
        p = NULL;
        if (fw != buf && fw[0] == 'j')
          p = fw;
        while (p && *p != ' ')
          p++;
        while (p && *p == ' ')
          p++;
        if (p != NULL) {
          memmove(p + 9, p, strlen(p) + 1);
          memcpy(p, "near ptr ", 9);
          jmp_near = 0;
        }
      }
      if (word_imm) {
        p = strstr(fw, ", ");
        if (p != NULL && '0' <= p[2] && p[2] <= '9') {
          p += 2;
          memmove(p + 9, p, strlen(p) + 1);
          memcpy(p, "word ptr ", 9);
        }
      }
      else if (dword_imm) {
        p = strstr(fw, ", ");
        if (p != NULL && '0' <= p[2] && p[2] <= '9') {
          p += 2;
          memmove(p + 10, p, strlen(p) + 1);
          memcpy(p, "dword ptr ", 10);
        }
      }
      else if (do_pushf) {
        p = strstr(fw, "pushf");
        if (p == NULL)
          p = strstr(fw, "popf");
        if (p != NULL) {
          p = strchr(p, 'f') + 1;
          memmove(p + 1, p, strlen(p) + 1);
          *p = 'd';
        }
      }

      if (fw[0] == 'a' && IS_START(fw, "assume cs")) {
        // "assume cs" causes problems with ext syms
        memmove(fw + 1, fw, strlen(fw) + 1);
        *fw = ';';
      }
      else if (fw[0] == 'e' && IS_START(fw, "end") && fw[3] == ' ') {
        fout_line++;
        qfprintf(fout, "include public.inc\n\n");

        // kill entry point
        fw[3] = 0;
      }

      fout_line++;
      qfprintf(fout, "%s\n", buf);
    }

    while (do_nops-- > 0)
      qfprintf(fout, "                nop ; adj\n");

    // note: next_head skips some undefined stuff
    ea = next_not_tail(ea); // correct?
    if (ea == BADADDR)
      break;

    pl.ea = ea;
    pl.lnnum = 0;
    ln.set_place(&pl);
  }

  if (fout != NULL)
    qfclose(fout);
  if (fname != NULL)
    qfree(fname);

  hide_wait_box();
  msg("%d lines saved.\n", fout_line);
}

//--------------------------------------------------------------------------

static const char comment[] = "Generate disassembly for nasm";
static const char help[] = "Generate asm file\n";
static const char wanted_name[] = "Save asm";
static const char wanted_hotkey[] = "Shift-S";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize
  term,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint
  help,                 // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};

// vim:ts=2:shiftwidth=2:expandtab
