int sub_test(const char * a1, ...)
{
  union { u32 d[128]; u8 b[512]; } sf;
  va_list ap;
  u32 eax;

  va_start(ap, a1);
  eax = (u32)&sf.d[0];  // var_200
  eax = _vsnprintf((char*)eax, 0x200, (const char*)a1, ap);  // arg_0
  va_end(ap);
  return eax;
}

