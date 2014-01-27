#define NO_OBSOLETE_FUNCS
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#include <name.hpp>
#include <frame.hpp>
#include <struct.hpp>
#include <auto.hpp>
#include <intel.hpp>

#define IS_START(w, y) !strncmp(w, y, strlen(y))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

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
  if (nonlocal_bt != NULL) {
    free(nonlocal_bt);
    nonlocal_bt = NULL;
  }
  nonlocal_bt_alloc = 0;
}

//--------------------------------------------------------------------------

static const char *reserved_names[] = {
  "name",
  "offset",
};

static int is_name_reserved(const char *name)
{
  int i;
  for (i = 0; i < ARRAY_SIZE(reserved_names); i++)
    if (strcasecmp(name, reserved_names[i]) == 0)
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

static void do_def_line(char *buf, size_t buf_size, const char *line)
{
  char *endp = NULL;
  ea_t ea, *ea_ret;
  int len;

  tag_remove(line, buf, buf_size); // remove color codes
  len = strlen(buf);
  if (len < 9) {
    buf[0] = 0;
    return;
  }
  memmove(buf, buf + 9, len - 9 + 1); // rm address

  if (IS_START(buf, "loc_")) {
    ea = strtoul(buf + 4, &endp, 16);
    if (ea != 0 && *endp == ':') {
      ea_ret = (ea_t *)bsearch(&ea, nonlocal_bt, nonlocal_bt_cnt,
        sizeof(nonlocal_bt[0]), nonlocal_bt_cmp);
      if (ea_ret != 0) {
        if (endp[1] != ' ')
          msg("no trailing blank in '%s'\n", buf);
        else
          endp[1] = ':';
      }
    }
  }
}

static void idaapi run(int /*arg*/)
{
  // isEnabled(ea) // address belongs to disassembly
  // ea_t ea = get_screen_ea();
  // foo = DecodeInstruction(ScreenEA());
  FILE *fout = NULL;
  int fout_line = 0;
  char buf[MAXSTR];
  int drop_large = 0;
  struc_t *frame;
  func_t *func;
  ea_t ui_ea_block = 0, ea_size;
  ea_t tmp_ea, target_ea;
  ea_t ea;
  int i, o, m, n;
  int ret;
  char *p;

  nonlocal_bt_cnt = 0;

  // 1st pass: walk through all funcs
  func = get_func(inf.minEA);
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

        if (is_name_reserved(buf)) {
          msg("%x: renaming '%s'\n", ea, buf);
          qstrncat(buf, "_", sizeof(buf));
          ret = set_member_name(frame, frame->members[m].soff, buf);
          if (!ret) {
            msg("%x: renaming failed\n", ea);
            return;
          }
        }

        tmp_ea = get_name_ea(ea, buf);
        if (tmp_ea == 0 || tmp_ea == ~0)
          continue;

        msg("%x: from %x: renaming '%s'\n", tmp_ea, ea, buf);
        qstrncat(buf, "_g", sizeof(buf));
        set_name(tmp_ea, buf);
      }
    }

    func = get_next_func(ea);
  }

  // 2nd pass over whole .text segment
  for (ea = inf.minEA; ea != BADADDR; ea = next_head(ea, inf.maxEA))
  {
    segment_t *seg = getseg(ea);
    if (!seg || seg->type != SEG_CODE)
      break;

    flags_t ea_flags = get_flags_novalue(ea);
    func = get_func(ea);
    if (isCode(ea_flags))
    {
      if (!decode_insn(ea)) {
        msg("%x: decode_insn() failed\n", ea);
        continue;
      }

      // find non-local branches
      if ((cmd.itype == NN_jmp || insn_jcc())
        && cmd.Operands[0].type == o_near)
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
      if (func == NULL && isOff0(ea_flags)) {
        ea_size = get_item_size(ea);
        for (tmp_ea = 0; tmp_ea < ea_size; tmp_ea += 4)
          nonlocal_add(get_long(ea + tmp_ea));
      }
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
    do_def_line(buf, sizeof(buf), ln.down());
    if (strstr(buf, "include"))
      continue;

    fout_line++;
    qfprintf(fout, "%s\n", buf);
    p = strstr(buf, ".mmx");
    if (p != NULL) {
      memcpy(p, ".xmm", 4);
      fout_line++;
      qfprintf(fout, "%s\n", buf);
    }
  }

  for (;;)
  {
    drop_large = 0;

    if ((ea >> 14) != ui_ea_block) {
      ui_ea_block = ea >> 14;
      showAddr(ea);
      if (wasBreak())
        break;
    }

    segment_t *seg = getseg(ea);
    if (!seg || seg->type != SEG_CODE)
      goto pass;
    if (!decode_insn(ea))
      goto pass;

    // note: decode_insn() picks up things like dd, size is then weird
    //cmd_size = cmd.size;

    for (o = 0; o < UA_MAXOP; o++) {
      if (cmd.Operands[o].type == o_void)
        break;

      if (cmd.Operands[o].type == o_mem
        && cmd.Operands[o].specval_shorts.high == 0x21) // correct?
      {
        drop_large = 1;
      }
#if 0
      if (cmd.Operands[o].type == o_displ && cmd.Operands[o].reg == 5) {
        member_t *m;

        m = get_stkvar(cmd.Operands[o], cmd.Operands[o].addr, NULL);
        if (m == NULL) {
          msg("%x: no stkvar for offs %x\n",
            ea, cmd.Operands[o].addr);
          goto out;
        }
        if (get_struc_name(m->id, buf, sizeof(buf)) <= 0) {
          msg("%x: stkvar with offs %x has no name?\n",
            ea, cmd.Operands[o].addr);
          goto out;
        }
        msg("%x: name '%s'\n", ea, buf);
      }
#endif
    }

pass:
    do_def_line(buf, sizeof(buf), ln.down());
    if (drop_large) {
      p = strstr(buf, "large ");
      if (p != NULL)
        memmove(p, p + 6, strlen(p + 6) + 1);
    }

    fout_line++;
    qfprintf(fout, "%s\n", buf);

    // note: next_head skips some undefined stuff
    ea = next_not_tail(ea); // correct?
    if (ea == BADADDR)
      break;

    pl.ea = ea;
    pl.lnnum = 0;
    ln.set_place(&pl);
    n = ln.get_linecnt();
    for (i = 0; i < n - 1; i++)
    {
      fout_line++;
      do_def_line(buf, sizeof(buf), ln.down());
      qfprintf(fout, "%s\n", buf);
    }
  }

  if (fout != NULL)
    qfclose(fout);
  if (fname != NULL)
    qfree(fname);

  hide_wait_box();
  msg("%d lines saved.\n", fout_line);
}

//--------------------------------------------------------------------------

static const char comment[] = "Generate disassembly lines for one address";
static const char help[] = "Generate asm file\n";
static const char wanted_name[] = "Save asm";
static const char wanted_hotkey[] = "Ctrl-F6";

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
