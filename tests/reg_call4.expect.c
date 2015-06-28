void call_test()
{
  u32 ebp;

  ebp = 1;
  ebpcall_func(ebp);  // tailcall
}

