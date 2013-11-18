
static inline void my_assert_(int line, const char *name, long v, long expect, int is_eq)
{
	int ok;
	if (is_eq)
		ok = (v == expect);
	else
		ok = (v != expect);

	if (!ok)
	{
		printf("%d: '%s' is %lx, need %s%lx\n", line, name,
			v, is_eq ? "" : "!", expect);
		exit(1);
	}
}
#define my_assert(v, exp) \
	my_assert_(__LINE__, #v, (long)(v), (long)(exp), 1)
#define my_assert_not(v, exp) \
	my_assert_(__LINE__, #v, (long)(v), (long)(exp), 0)


