int sub_test(int a1, int a2)
{
  union { u32 d[8]; u16 w[16]; u8 b[32]; double q[4]; } sf;
  u32 eax;
  u32 edx;
  double f_st0;
  double f_st1;
  u16 f_sw;
  double fs_1;
  double fs_3;
  u32 cond_z;

  f_st0 = (double)(s32)sf.d[0];  // var_20 fild
  f_st0 /= (double)(s32)a1;  // arg_0
  f_st0 *= sf.q[1];  // var_18
  f_st1 = f_st0;  f_st0 = (double)(s32)sf.d[0];  // var_20 fild
  f_st1 /= f_st0;
  f_st0 = f_st1 + f_st0;
  f_st1 = f_st0;  f_st0 = sf.q[1];  // var_18 fld
  fs_3 = f_st0;  f_st0 = f_st1;  // fst
  fs_1 = f_st0;  // fst
  f_st0 = pow(fs_1, fs_3);
  f_sw = f_st0 <= sf.q[1] ? 0x4100 : 0;  // var_18 z_chk_det
  eax = 0;
  LOWORD(eax) = f_sw;
  cond_z = ((u8)((u8)(eax >> 8) & 0x41) == 0);
  eax = 0;
  LOBYTE(eax) = (cond_z);
  f_st1 = f_st0;  f_st0 = 1.0;
  f_st0 = sf.q[1] / f_st0;  // var_18
  { double t = f_st0; f_st0 = f_st1; f_st1 = t; }  // fxch
  f_st0 = -f_st0;
  f_st0 = f_st1;
  f_st1 = f_st0;  // fld st
  f_st0 = f_st1 * log2(f_st0);  // fyl2x
  f_st1 = f_st0;  // fld st
  sf.d[0] = (s32)f_st0;  f_st0 = f_st1;  // var_20 fist
  sf.q[1] = f_st0;  // var_18 fst
  eax = (s32)f_st0;  // ftol
  return eax;
}

