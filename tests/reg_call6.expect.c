void __fastcall sub_test(int a1, int a2)
{
  u32 ecx = (u32)a1;
  u32 edx = (u32)a2;
  u32 s_a3;
  u32 s_a4;

  s_a4 = ecx;
  ecx <<= 9;
  s_a3 = edx;
  edx &= 0x7f;
  ecx += 1;
  sub_test2(ecx, edx, s_a3, s_a4);

}

