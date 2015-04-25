int sub_test()
{
  union { u32 d[1]; u8 b[4]; } sf;
  u32 eax;
  u32 edx;
  float f_st0;
  float f_st1;

  sf.d[0] = 4;  // var_4
  f_st0 = (float)(s32)sf.d[0];  // var_4 fild
  f_st1 = f_st0;  f_st0 = (float)(s32)sf.d[0];  // var_4 fild
  f_st0 = sqrtf(f_st0);
  f_st0 = atanf(f_st1 / f_st0);
  eax = (s32)f_st0;  // ftol
  return eax;
}

