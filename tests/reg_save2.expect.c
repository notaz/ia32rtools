int __fastcall sub_test(int a1)
{
  u32 ecx = (u32)a1;
  u32 eax;

  if (ecx == 0)
    goto loc1;
  eax = 0;
  goto end;

loc1:
  eax = 1;

end:
  return eax;
}

