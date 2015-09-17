static unsigned long parse_number(const char *number)
{
  int len = strlen(number);
  const char *p = number;
  char *endp = NULL;
  unsigned long ret;
  int neg = 0;
  int bad;

  if (*p == '-') {
    neg = 1;
    p++;
  }
  if (len > 1 && *p == '0')
    p++;
  if (number[len - 1] == 'h') {
    ret = strtoul(p, &endp, 16);
    bad = (*endp != 'h');
  }
  else {
    ret = strtoul(p, &endp, 10);
    bad = (*endp != 0);
  }
  if (bad)
    aerr("number parsing failed (%s)\n", number);
#if __SIZEOF_LONG__ > 4
  // if this happens, callers must be fixed too
  if (ret > 0xfffffffful)
    aerr("number too large? (%s)\n", number);
#endif
  if (neg) {
    if (ret > 0x7fffffff)
      aerr("too large negative? (%s)\n", number);
    ret = -ret;
  }
  return ret;
}

