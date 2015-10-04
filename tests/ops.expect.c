int sub_test()
{
  u32 eax;
  u32 ebx;
  u32 ecx;
  u32 edx;
  u32 esi;
  u32 edi;
  u32 cond_c;
  u32 cond_z;
  u64 tmp64;

  ebx = 0x10000;
  esi = 0x20000;
  edi = 0x30000;
  ecx = 0x0a;

loop:
  LOBYTE(eax) = *(u8 *)esi; esi += 1;  // lods
  LOBYTE(eax) = *(u8 *)(ebx + LOBYTE(eax));  // xlat
  *(u8 *)edi = eax; edi += 1;  // stos
  LOWORD(eax) = *(u16 *)esi; esi += 2;  // lods
  LOWORD(eax) = -(s16)(u16)eax;
  *(u16 *)edi = eax; edi += 2;  // stos
  eax = *(u32 *)esi; esi += 4;  // lods
  *(u32 *)edi = eax; edi += 4;  // stos
  *(u8 *)edi = *(u8 *)esi; edi += 1; esi += 1;  // movs
  cond_z = (*(u16 *)esi == *(u16 *)edi); esi += 2; edi += 2;  // cmps
  cond_z = ((u8)eax == *(u8 *)edi); edi += 1;  // scas
  if (--ecx != 0)
    goto loop;  // loop
  *(u8 *)edi = eax; edi -= 1;  // stos
  *(u16 *)edi = eax; edi -= 2;  // stos
  *(u32 *)edi = eax; edi -= 4;  // stos
  edx = (s32)eax >> 31;  // cdq
  if (ecx) eax = __builtin_ffs(ecx) - 1;  // bsf
  tmp64 = ((u64)edx << 32) | eax;
  tmp64 = (s64)tmp64 << LOBYTE(ecx);
  edx = tmp64 >> 32; eax = tmp64;  // allshl
  edi = eax;
  tmp64 = ((u64)edx << 32) | eax;
  tmp64 = (s64)tmp64 >> LOBYTE(ecx);
  edx = tmp64 >> 32; eax = tmp64;  // allshr
  eax = __builtin_bswap32(eax);
  ecx ^= eax;
  tmp64 = (u64)eax + ecx;
  cond_c = tmp64 >> 32;
  eax = (u32)tmp64;
  cond_z = (eax == 0);  // add64
  while (ecx != 0) {
    cond_c = *(u8 *)esi < *(u8 *)edi;
    cond_z = (*(u8 *)esi == *(u8 *)edi); esi += 1, edi += 1;
    ecx--;
    if (cond_z != 0) break;
  }  // repne cmps
  LOBYTE(ecx) = (!cond_z);
  LOBYTE(ecx) += (u8)ecx + cond_c;
  eax = 1;
  return eax;
}

