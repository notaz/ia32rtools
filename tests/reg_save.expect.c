int sub_test()
{
  u32 eax;
  u32 ebx;
  u32 s_ebx;

  ebx = 1;
  s_ebx = ebx;
  ebx = 2;
  ebx = s_ebx;
  eax = 0xffffffff;
  return eax;
}

