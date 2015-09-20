void __stdcall sub_test(int a1)
{
  a1 += 1;  // arg_0
  if ((u32)a1 == 0)
    goto return_;  // arg_0
  another_func(a1);
  return;  // ^ tailcall argframe

return_:
  return;
}

