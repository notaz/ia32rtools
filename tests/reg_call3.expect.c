void __fastcall sub_test()
{
  u32 ebx;
  u32 ecx = 0;
  u32 edx = 0;

  ebx = 0;
  fastcall_func(ecx, edx, 1);  // tailcall
}

