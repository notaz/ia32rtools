int __fastcall sub_test(int a1, int a2)
{
  u32 ecx = (u32)a1;
  u32 edx = (u32)a2;
  u32 ebx;

  ebx = 1;
  return fastcall_func(ecx, edx);  // tailcall
}

