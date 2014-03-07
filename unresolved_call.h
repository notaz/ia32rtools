#define unresolved_call(n, p) do {\
  printf("%s: unresolved_call %p %s\n", n, p, addr_to_sym(p)); \
  fflush(stdout); \
} while (0)

/* mingw is missing dbghelp stuff.. */
static const char *addr_to_sym(void *addr)
{
  static HMODULE dbgh;
  static BOOL WINAPI (*pSymFromAddr)(HANDLE hProcess, DWORD64 Address, 
                      DWORD64* Displacement, void *Symbol);
  static BOOL WINAPI (*pSymInitialize)(HANDLE hProcess,
                      PCSTR UserSearchPath, BOOL fInvadeProcess);
  static char info[88 + 256];

  if (dbgh == NULL)
    dbgh = LoadLibraryA("dbghelp.dll");
  if (dbgh == NULL)
    return "(no dbghelp)";
  if (pSymFromAddr == NULL)
    pSymFromAddr = (void *)GetProcAddress(dbgh, "SymFromAddr");
  if (pSymFromAddr == NULL)
    return "(no SymFromAddr)";
  if (pSymInitialize == NULL) {
    pSymInitialize = (void *)GetProcAddress(dbgh, "SymInitialize");
    if (pSymInitialize == NULL)
      return "(no SymInitialize)";
    pSymInitialize(GetCurrentProcess(), NULL, TRUE);
  }

  *(ULONG *)&info[0] = 88; // SizeOfStruct
  *(ULONG *)&info[80] = 256; // MaxNameLen
  if (!pSymFromAddr(GetCurrentProcess(), (DWORD64)(unsigned int)addr, NULL, info))
      return "(no sym)";

  return info + 84;
}

