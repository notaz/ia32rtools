/*
 * ia32rtools
 * header simplification -
 * output only stack args forced to basic types
 *
 * (C) notaz, 2013-2015
 *
 * This work is licensed under the terms of 3-clause BSD license.
 * See COPYING file in the top-level directory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "my_assert.h"
#include "my_str.h"
#include "common.h"

#include "protoparse.h"

static const char *output_type(const struct parsed_type *type)
{
  if (type->is_float)
    return "float";
  else if (type->is_64bit)
    return "__int64";
  else if (IS(type->name, "void"))
    return "void";
  else
    return "int";
}

int main(int argc, char *argv[])
{
  const struct parsed_proto *pp;
  FILE *fhdr, *fout;
  int i, a, a_out;

  if (argc != 3) {
    printf("usage:\n%s <hdr_out.h> <hdr_in.h>\n", argv[0]);
    return 1;
  }

  hdrfn = argv[2];
  fhdr = fopen(hdrfn, "r");
  my_assert_not(fhdr, NULL);
  fout = fopen(argv[1], "w");
  my_assert_not(fout, NULL);

  build_caches(fhdr);

  for (i = 0; i < pp_cache_size; i++) {
    pp = &pp_cache[i];
    if (!pp->is_func || pp->is_fptr || pp->is_osinc)
      continue;

    if (pp->argc_reg != 0)
      fprintf(fout, "// %d reg args\n", pp->argc_reg);
    fprintf(fout, "%-4s ", output_type(&pp->ret_type));
    if (!pp->is_stdcall || pp->argc_stack == 0)
      fprintf(fout, "__cdecl   ");
    else
      fprintf(fout, "__stdcall ");
    fprintf(fout, "%s(", pp->name);

    for (a = a_out = 0; a < pp->argc; a++) {
      if (pp->arg[a].reg != NULL || pp->arg[a].type.is_retreg)
        continue;
      if (a_out++ > 0)
        fprintf(fout, ", ");
      fprintf(fout, "%s", output_type(&pp->arg[a].type));
      if (pp->arg[a].type.is_64bit)
        a++;
    }
    if (pp->is_vararg) {
      if (a_out > 0)
        fprintf(fout, ", ");
      fprintf(fout, "...");
    }
    fprintf(fout, ");\n");
  }

  fclose(fhdr);
  fclose(fout);
  (void)proto_parse;

  return 0;
}

// vim:ts=2:shiftwidth=2:expandtab
