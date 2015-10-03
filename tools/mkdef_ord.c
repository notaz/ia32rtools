/*
 * ia32rtools
 * (C) notaz, 2013,2014
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

int main(int argc, char *argv[])
{
  const struct parsed_proto *pp;
  FILE *fout, *fhdr;
  char basename[256] = { 0, };
  char line[256];
  char fmt[256];
  char word[256];
  int noname = 0;
  const char *p2;
  char *p;
  int arg;
  int ret, ord;
  int l;

  for (arg = 1; arg < argc; arg++) {
    if (IS(argv[arg], "-n"))
      noname = 1;
    else if (IS(argv[arg], "-b") && arg < argc - 1)
      snprintf(basename, sizeof(basename), "%s", argv[++arg]);
    else
      break;
  }

  if (argc != arg + 2) {
    printf("usage:\n%s [-n] [-b <basename>] <.h> <.def>\n", argv[0]);
    return 1;
  }

  hdrfn = argv[arg++];
  fhdr = fopen(hdrfn, "r");
  my_assert_not(fhdr, NULL);

  fout = fopen(argv[arg++], "w");
  my_assert_not(fout, NULL);

  if (basename[0] == 0) {
    p = strrchr(hdrfn, '.');
    my_assert_not(p, NULL);
    p2 = strrchr(hdrfn, '/');
    if (p2++ == NULL)
      p2 = hdrfn;
    l = p - p2;
    my_assert((unsigned int)l < 256, 1);
    memcpy(basename, p2, l);
    basename[l] = 0;
  }

  snprintf(fmt, sizeof(fmt), "%s_%%d", basename);

  fprintf(fout, "LIBRARY %s\n", basename);
  fprintf(fout, "EXPORTS\n");

  while (fgets(line, sizeof(line), fhdr))
  {
    p = sskip(line);
    if (*p == 0)
      continue;

    if (IS_START(p, "//"))
      continue;

    ret = 0;
    while (p != NULL && *p != 0) {
      p = next_word(word, sizeof(word), p);
      ret = sscanf(word, fmt, &ord);
      if (ret == 1)
        break;
    }
    if (ret != 1) {
      printf("scan for '%s' failed for '%s'\n", fmt, line);
      return 1;
    }

    snprintf(word, sizeof(word), fmt, ord);
    pp = proto_parse(fhdr, word, 0);
    if (pp == NULL)
      return 1;

    fputc(' ', fout);
    fputc(pp->is_fastcall ? '@' : ' ', fout);
    fprintf(fout, "%s", word);
    if (pp->is_stdcall)
      fprintf(fout, "@%-2d", pp->argc * 4);
    else
      fprintf(fout, "   ");
    fprintf(fout, " @%d", ord);
    if (noname)
      fprintf(fout, " NONAME");
    fprintf(fout, "\n");
  }

  fclose(fhdr);
  fclose(fout);
  return 0;
}

// vim:ts=2:shiftwidth=2:expandtab
