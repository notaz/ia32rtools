int sub_test()
{
  union { u32 d[2]; u8 b[8]; } sf;
  u32 eax;

  sf.d[0] = 1;  // var_8
  ebpcall_func((u32)&sf.b[sizeof(sf)]);  // bp_ref
  eax = 0;
  return eax;
}

