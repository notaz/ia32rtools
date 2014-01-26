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

#define IS_START(w, y) !strncmp(w, y, strlen(y))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

//--------------------------------------------------------------------------
static int idaapi init(void)
{
  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
static void idaapi term(void)
{
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

static void do_def_line(char *buf, size_t buf_size, const char *line)
{
  int len;

  tag_remove(line, buf, buf_size); // remove color codes
  len = strlen(buf);
  if (len < 9) {
    buf[0] = 0;
    return;
  }
  memmove(buf, buf + 9, len - 9 + 1); // rm address
}

static void idaapi run(int /*arg*/)
{
  //  isEnabled(ea) // address belongs to disassembly
  // ea_t ea = get_screen_ea();
  // nextaddr(ea) - no worky?
  FILE *fout = NULL;
  int fout_line = 0;
  char buf[MAXSTR];
  struc_t *frame;
  func_t *func;
  ea_t ui_ea_block = 0;
  ea_t tmp_ea;
  ea_t ea;
  int i, o, m, n;
  int ret;
  char *p;

  // rename global syms which conflict with frame member names
  ea = inf.minEA;
  func = get_next_func(ea);
  while (func != NULL)
  {
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
    if (func)
      ea = get_next_func_addr(func, ea);
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

    }

pass:
    fout_line++;
    do_def_line(buf, sizeof(buf), ln.down());
    qfprintf(fout, "%s\n", buf);

    ea = next_not_tail(ea); // correct?
    if (ea == 0 || ea == ~0)
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
