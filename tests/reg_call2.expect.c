int __fastcall sub_test(int a1, int a2)
{
  u32 ecx = (u32)a1;
  // edx = a2; // unused
  u32 eax;

  eax = fastcall_func(ecx);
  ecx++;
  return eax;
}

