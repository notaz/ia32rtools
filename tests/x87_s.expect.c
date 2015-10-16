double sub_test()
{
  union { u32 d[1]; u8 b[4]; double q[1]; } sf;
  float f_st[8];
  int f_stp = 0;

  sf.d[0] = 4;  // var_4
  f_st[--f_stp & 7] = (float)(s32)sf.d[0];  // var_4 fild
  f_st[--f_stp & 7] = *(float *)((u32)&sf.d[0]);  // var_4 fld
  f_st[--f_stp & 7] = (float)(s32)sf.d[0];  // var_4 fild
  f_st[--f_stp & 7] = 1.0;
  f_st[--f_stp & 7] = (float)(s32)sf.d[0];  // var_4 fild
  f_st[--f_stp & 7] = 0.0;
  f_st[--f_stp & 7] = M_LN2;
  f_st[--f_stp & 7] = (float)(s32)sf.d[0];  // var_4 fild
  f_stp++;
  f_st[(f_stp + 5) & 7] /= f_st[f_stp & 7];  f_stp++;
  f_st[(f_stp + 1) & 7] = f_st[(f_stp + 1) & 7] * log2f(f_st[f_stp & 7]); f_stp++;  // fyl2x
  f_st[(f_stp + 2) & 7] -= f_st[f_stp & 7];  f_stp++;
  f_stp++;
  { float t = f_st[f_stp & 7]; f_st[f_stp & 7] = f_st[(f_stp + 6) & 7]; f_st[(f_stp + 6) & 7] = t; }  // fxch
  f_st[f_stp & 7] = -f_st[f_stp & 7];
  f_st[(f_stp + 1) & 7] = atanf(f_st[(f_stp + 1) & 7] / f_st[f_stp & 7]); f_stp++;
  sf.d[0] = (s32)f_st[f_stp & 7];  // var_4 fist
  *(float *)((u32)&sf.d[0]) = f_st[f_stp & 7];  f_stp++;  // var_4 fst
  return f_st[f_stp & 7];
}

