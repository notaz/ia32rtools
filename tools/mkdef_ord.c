#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "my_assert.h"
#include "my_str.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define IS(w, y) !strcmp(w, y)
#define IS_START(w, y) !strncmp(w, y, strlen(y))

#include "protoparse.h"

int main(int argc, char *argv[])
{
  const struct parsed_proto *pp;
  FILE *fout, *fhdr;
  char basename[256];
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
    else
      break;
  }

  if (argc != arg + 2) {
    printf("usage:\n%s [-n] <.h> <.def>\n", argv[0]);
    return 1;
  }

  hdrfn = argv[arg++];
  fhdr = fopen(hdrfn, "r");
  my_assert_not(fhdr, NULL);

  fout = fopen(argv[arg++], "w");
  my_assert_not(fout, NULL);

  p = strrchr(hdrfn, '.');
  my_assert_not(p, NULL);
  p2 = strrchr(hdrfn, '/');
  if (p2++ == NULL)
    p2 = hdrfn;
  l = p - p2;
  my_assert((unsigned int)l < 256, 1);
  memcpy(basename, p2, l);
  basename[l] = 0;

  snprintf(fmt, sizeof(fmt), "%s_%%d", basename);

  fprintf(fout, "LIBRARY %s\n", basename);
  fprintf(fout, "EXPORTS\n");

  while (fgets(line, sizeof(line), fhdr))
  {
    p = sskip(line);
    if (*p == 0)
      continue;

    if (IS(p, "//"))
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

    fprintf(fout, "  %s", word);
    if (pp->is_stdcall)
      fprintf(fout, "@%-2d", pp->argc_stack * 4);
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
