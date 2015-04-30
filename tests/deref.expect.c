int sub_test()
{
  void (__stdcall *i_f0)(int);
  int (__stdcall *i_f1)(int);
  u32 eax;
  u32 esi;

  esi = (u32)ptr_struct1;
  i_f0 = (void *)*(u32 *)(esi);
  i_f0(1);
  eax = *(u32 *)(esi+4);
  i_f1 = (void *)*(u32 *)(eax+4);
  eax = i_f1(2);
  return eax;
}

