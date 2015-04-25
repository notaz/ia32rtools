int sub_test(int a1, int a2)
{
  union { u32 d[8]; u8 b[32]; double q[4]; } sf;
  u32 eax;
  u32 edx;
  double f_st0;
  double f_st1;

  f_st0 = (double)(s32)sf.d[0];  // var_20 fild
  f_st0 /= (double)(s32)a1;  // arg_0
  f_st0 *= *((double *)(u32)&sf.q[1]);  // var_18
  f_st1 = f_st0;  f_st0 = (double)(s32)sf.d[0];  // var_20 fild
  f_st1 /= f_st0;
  f_st0 = f_st1 + f_st0;
  f_st1 = f_st0;  f_st0 = 1.0;
  f_st0 = *((double *)(u32)&sf.q[1]) / f_st0;  // var_18
  { double t = f_st0; f_st0 = f_st1; f_st1 = t; }  // fxch
  f_st0 = -f_st0;
  f_st0 = f_st1;
  f_st1 = f_st0;  // fld st
  f_st0 = f_st1 * log2(f_st0);
  f_st1 = f_st0;  // fld st
  *((double *)(u32)&sf.q[1]) = f_st0;  f_st0 = f_st1;  // var_18 fst
  *((float *)(u32)&sf.d[0]) = f_st0;  // var_20 fst
  eax = (s32)f_st0;  // ftol
  return eax;
}

