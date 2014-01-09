#if __SIZEOF_LONG__ != 8
#error fix ret/strtoul to do 64bit
#endif

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
  if (neg)
    ret = -ret;
  return ret;
}


