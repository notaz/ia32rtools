/*
 * ia32rtools
 * (C) notaz, 2015
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

static void idaapi run(int /*arg*/)
{
  bool found = false;
  flags_t ea_flags;
  uint32 val;
  ea_t ea;

  ea = get_screen_ea();
  // msg("range: %x/%x-%x\n", ea, inf.minEA, inf.maxEA);

  ea = next_unknown(ea, inf.maxEA);
  for (; ea != BADADDR; ea = next_unknown(ea, inf.maxEA))
  {
    segment_t *seg = getseg(ea);
    if (!seg)
      break;
    if (seg->type != SEG_DATA)
      continue;

    ea_flags = getFlags(ea);
    if (!hasValue(ea_flags))
      continue;
    val = get_long(ea);
    if (inf.minEA <= val && val < inf.maxEA) {
      found = 1;
      break;
    }
  }

  if (found) {
    // msg("%x: jmp\n", ea);
    jumpto(ea);
  }
  else
    msg("end reached.\n");
}

//--------------------------------------------------------------------------

static const char comment[] = "Find next pointer-like data";
static const char help[] = "Find next pointer-like data\n";
static const char wanted_name[] = "Find next ptr-like";
static const char wanted_hotkey[] = "Shift-N";

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
