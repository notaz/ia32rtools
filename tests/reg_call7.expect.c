int __fastcall sub_test(int a1)
{
  u32 ecx = (u32)a1;
  u32 eax;
  u32 ebx;
  u32 s_a1;
  u32 s1_a1;
  u32 s1_a2;
  u32 s1_a3;
  u32 s1_a4;
  u32 s1_a5;

  ecx += 1;
  s1_a5 = ecx;
  ebx = ecx;
  s1_a4 = ebx;
  ebx += 1;
  if (ebx == 0)
    goto l4;
  if ((s32)ebx >= 0)
    goto l2;
  sub_test1(s1_a4);
  s1_a4 = ebx;
  ebx += 1;

l2:
  sub_test2(s1_a4);
  s1_a5 = ebx;
  ebx += 1;

back:
  s1_a4 = ebx;
  ebx += 1;
  if (ebx == 0)
    goto l4;
  s1_a3 = ebx;
  ebx += 1;
  if (ebx != 0)
    goto l5;
  sub_test3(s1_a3, s1_a4, s1_a5);
  s1_a5 = ebx;
  ebx += 1;
  if (ebx == 0)
    goto back;
  s1_a4 = ebx;
  ebx += 1;

l4:
  s1_a1 = ebx;
  ebx += 1;
  sub_test4(s1_a1, s1_a4, s1_a5);
  s1_a4 = ebx;
  ebx += 1;
  s1_a3 = ebx;
  ebx += 1;

l5:
  s1_a2 = ebx;
  ebx += 1;
  s1_a1 = ebx;
  ebx += 1;
  s_a1 = ebx;
  ebx += 1;
  sub_test6(s_a1);
  sub_test5(s1_a1, s1_a2, s1_a3, s1_a4);
  eax = ebx;
  return eax;
}

