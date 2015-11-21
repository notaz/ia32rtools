// note: include after system headers

//#pragma GCC diagnostic ignored "-Wparentheses"

#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t
#define s8 int8_t
#define s16 int16_t
#define s32 int32_t
#define s64 int64_t
typedef struct {
  u64 q;
  u32 d[2];
  u16 w[4];
  u8  b[8];
} mmxr;

#define bool int
#define _BYTE uint8_t
#define _WORD uint16_t
#define _DWORD uint32_t
#define _UNKNOWN uint8_t
#undef LOBYTE
#undef LOWORD
#undef HIBYTE
#undef HIWORD
#define LOBYTE(x)   (*((u8*)&(x)))
#define LOWORD(x)   (*((u16*)&(x)))
#define HIBYTE(x)   (*((u8*)&(x)+1))
#define HIWORD(x)   (*((u16*)&(x)+1))
#define BYTE0(x)    (*((u8*)&(x)+0))
#define BYTE1(x)    (*((u8*)&(x)+1))
#define BYTE2(x)    (*((u8*)&(x)+2))
#define BYTE3(x)    (*((u8*)&(x)+3))

#ifndef __WINE__
#define DECL_IMPORT __declspec(dllimport)
#else
#define DECL_IMPORT
#endif

#define memcpy_0 memcpy

#define noreturn __attribute__((noreturn))

static inline BOOL PtInRect_sa(LPCRECT r, int x, int y)
{
  POINT p = { x, y };
  return PtInRect(r, p);
}

static inline int do_parity(unsigned int v)
{
  v ^= v >> 4;
  v ^= v >> 2;
  v ^= v >> 1;
  return (v ^ 1) & 1;
}

#define do_skip_code_abort() \
  printf("%s:%d: skip_code_abort\n", __FILE__, __LINE__); \
  *(volatile int *)0 = 1

#define barrier() \
  asm volatile("" ::: "memory")

/* gcc always emits vldr/vstr which requires alignment,
 * so in some cases these unaligned helpers are needed */
#ifdef __ARM_NEON__

static inline float float_load(u32 ptr)
{
	register float v asm("s0");

	asm ("vld1.32  {d0[0]}, [%1]"
		: "=t"(v) : "r"(ptr));

	return v;
}

static inline void float_store(float v, u32 ptr)
{
	register float v1 asm("s0") = v;

	asm ("vst1.32  {d0[0]}, [%1]"
		: : "t"(v1), "r"(ptr) : "memory");
}

#else

static inline float float_load(u32 ptr)
{
	return *(const float *)ptr;
}

static inline void float_store(float v, u32 ptr)
{
	*(float *)ptr = v;
}

#endif

// vim:ts=2:sw=2:expandtab
