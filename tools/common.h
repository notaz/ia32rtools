// read a line, truncating it if it doesn't fit
static char *my_fgets(char *s, size_t size, FILE *stream)
{
  char *ret, *ret2;
  char buf[64];
  int p;

  p = size - 2;
  if (p >= 0)
    s[p] = 0;

  ret = fgets(s, size, stream);
  if (ret != NULL && p >= 0 && s[p] != 0 && s[p] != '\n') {
    p = sizeof(buf) - 2;
    do {
      buf[p] = 0;
      ret2 = fgets(buf, sizeof(buf), stream);
    }
    while (ret2 != NULL && buf[p] != 0 && buf[p] != '\n');
  }

  return ret;
}

