#include <errno.h>
#include <stdint.h>

static uint64_t parse_number(const char *number, int is64)
{
  int len = strlen(number);
  const char *p = number;
  char *endp = NULL;
  uint64_t ret;
  int neg = 0;
  int bad;

  if (*p == '-') {
    neg = 1;
    p++;
  }
  if (len > 1 && *p == '0')
    p++;

  errno = 0;
  if (number[len - 1] == 'h') {
    ret = strtouq(p, &endp, 16);
    bad = (*endp != 'h');
  }
  else {
    ret = strtouq(p, &endp, 10);
    bad = (*endp != 0);
  }
  if (errno != 0 || bad)
    aerr("number parsing failed (%s): %d\n", number, errno);
  // if this happens, callers must be fixed too
  if (!is64 && ret > 0xfffffffful)
    aerr("number too large? (%s)\n", number);
  if (neg) {
    if (!is64 && ret > 0x7fffffff)
      aerr("too large negative? (%s)\n", number);
    ret = -ret;
  }
  return ret;
}

