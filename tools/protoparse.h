/*
 * ia32rtools
 * (C) notaz, 2013,2014
 *
 * This work is licensed under the terms of 3-clause BSD license.
 * See COPYING file in the top-level directory.
 */

struct parsed_proto;

struct parsed_type {
	char *name;
	unsigned int is_array:1;
	unsigned int is_ptr:1;
	unsigned int is_struct:1; // split for args
	unsigned int is_retreg:1; // register to return to caller
	unsigned int is_va_list:1;
	unsigned int is_64bit:1;
	unsigned int is_float:1;  // float, double
};

struct parsed_proto_arg {
	char *reg;
	struct parsed_type type;
	struct parsed_proto *pp; // fptr or struct
	unsigned int is_saved:1; // not set here, for tool use
	void **push_refs;
	int push_ref_cnt;
};

struct parsed_proto {
	char name[256];
	union {
		struct parsed_type ret_type;
		struct parsed_type type;
	};
	struct parsed_proto_arg arg[32];
	int argc;
	int argc_stack;
	int argc_reg;
	unsigned int is_func:1;
	unsigned int is_stdcall:1;
	unsigned int is_fastcall:1;
	unsigned int is_vararg:1;     // vararg func
	unsigned int is_fptr:1;
	unsigned int is_import:1;     // data import
	unsigned int is_noreturn:1;
	unsigned int is_unresolved:1;
	unsigned int is_guessed:1;    // for extra checking
	unsigned int is_userstack:1;
	unsigned int is_include:1;    // not from top-level header
	unsigned int is_osinc:1;      // OS/system library func
	unsigned int is_cinc:1;       // crt library func
	unsigned int is_arg:1;        // declared in some func arg
	unsigned int has_structarg:1;
	unsigned int has_retreg:1;
};

struct parsed_struct {
	char name[256];
	struct {
		int offset;
		struct parsed_proto pp;
	} members[64];
	int member_count;
};

static const char *hdrfn;
static int hdrfline = 0;

static void pp_copy_arg(struct parsed_proto_arg *d,
	const struct parsed_proto_arg *s);

static int b_pp_c_handler(char *proto, const char *fname,
	int is_include, int is_osinc, int is_cinc);
static int struct_handler(FILE *fhdr, char *proto, int *line);

static int do_protostrs(FILE *fhdr, const char *fname, int is_include)
{
	const char *finc_name;
	const char *hdrfn_saved;
	char protostr[256];
	char path[256];
	char fname_inc[256];
	int is_osinc;
	int is_cinc;
	FILE *finc;
	int line = 0;
	int ret;
	char *p;

	hdrfn_saved = hdrfn;
	hdrfn = fname;

	is_cinc = strstr(fname, "stdc.hlist") != NULL;
	is_osinc = is_cinc || strstr(fname, "win32.hlist") != NULL;

	while (fgets(protostr, sizeof(protostr), fhdr))
	{
		line++;
		if (strncmp(protostr, "//#include ", 11) == 0) {
			finc_name = protostr + 11;
			p = strpbrk(finc_name, "\r\n ");
			if (p != NULL)
				*p = 0;

			path[0] = 0;
			p = strrchr(hdrfn_saved, '/');
			if (p) {
				memcpy(path, hdrfn_saved,
					p - hdrfn_saved + 1);
				path[p - hdrfn_saved + 1] = 0;
			}
			snprintf(fname_inc, sizeof(fname_inc), "%s%s", 
				path, finc_name);
			finc = fopen(fname_inc, "r");
			if (finc == NULL) {
				printf("%s:%d: can't open '%s'\n",
					fname_inc, line, finc_name);
				continue;
			}
			ret = do_protostrs(finc, finc_name, 1);
			fclose(finc);
			if (ret < 0)
				break;
			continue;
		}
		if (strncmp(sskip(protostr), "//", 2) == 0)
			continue;

		p = protostr + strlen(protostr);
		for (p--; p >= protostr && my_isblank(*p); --p)
			*p = 0;
		if (p < protostr)
			continue;

		hdrfline = line;

		if (!strncmp(protostr, "struct", 6)
		    && strchr(protostr, '{') != NULL)
			ret = struct_handler(fhdr, protostr, &line);
		else
			ret = b_pp_c_handler(protostr, hdrfn,
				is_include, is_osinc, is_cinc);
		if (ret < 0)
			break;
	}

	hdrfn = hdrfn_saved;

	if (feof(fhdr))
		return 0;

	return -1;
}

static int get_regparm(char *dst, size_t dlen, char *p, int *retreg)
{
	int i = 0, o;

	*retreg = 0;

	if (*p != '<')
		return 0;

	i++;
	if (p[i] == '*') {
		*retreg = 1;
		i++;
	}

	for (o = 0; o < dlen; i++) {
		if (p[i] == 0)
			return 0;
		if (p[i] == '>')
			break;
		dst[o++] = p[i];
	}
	dst[o] = 0;
	return i + 1;
}

// hmh..
static const char *known_type_mod[] = {
	"const",
	"signed",
	"unsigned",
	"enum",
	"CONST",
	"volatile",
};

static const char *known_ptr_types[] = {
	"FARPROC",
	"WNDPROC",
	"LINECALLBACK",
	"HACCEL",
	"HANDLE",
	"HBITMAP",
	"HBRUSH",
	"HCALL",
	"HCURSOR",
	"HDC",
	"HFONT",
	"HGDIOBJ",
	"HGLOBAL",
	"HHOOK",
	"HICON",
	"HINSTANCE",
	"HIMC", // DWORD in mingw, ptr in wine..
	"HLINE",
	"HLINEAPP",
	"HLOCAL",
	"HMODULE",
	"HPALETTE",
	"HRGN",
	"HRSRC",
	"HKEY",
	"HKL",
	"HMENU",
	"HMONITOR",
	"HWAVEOUT",
	"HWND",
	"PAPPBARDATA",
	"PBYTE",
	"PCRITICAL_SECTION",
	"PDEVMODEA",
	"PDWORD",
	"PFILETIME",
	"PLARGE_INTEGER",
	"PHANDLE",
	"PHKEY",
	"PLONG",
	"PMEMORY_BASIC_INFORMATION",
	"PUINT",
	"PULARGE_INTEGER",
	"PULONG_PTR",
	"PVOID",
	"PCVOID",
	"PWORD",
	"REFCLSID",
	"REFGUID",
	"REFIID",
	"SC_HANDLE",
	"SERVICE_STATUS_HANDLE",
	"HOOKPROC",
	"DLGPROC",
	"TIMERPROC",
	"WNDENUMPROC",
	"va_list",
	"__VALIST",
};

static const char *ignored_keywords[] = {
	"extern",
	"static",
	"WINBASEAPI",
	"WINUSERAPI",
	"WINGDIAPI",
	"WINADVAPI",
};

static int typecmp(const char *n, const char *t)
{
	for (; *t != 0; n++, t++) {
		while (n[0] == ' ' && (n[1] == ' ' || n[1] == '*'))
			n++;
		while (t[0] == ' ' && (t[1] == ' ' || t[1] == '*'))
			t++;
		if (*n != *t)
			return *n - *t;
	}

	return 0;
}

static const char *skip_type_mod(const char *n)
{
	int len;
	int i;

	for (i = 0; i < ARRAY_SIZE(known_type_mod); i++) {
		len = strlen(known_type_mod[i]);
		if (strncmp(n, known_type_mod[i], len) != 0)
			continue;
		if (!my_isblank(n[len]))
			continue;

		n += len;
		while (my_isblank(*n))
			n++;
		i = 0;
	}

	return n;
}

static int check_type(const char *name, struct parsed_type *type)
{
	const char *n, *n1;
	int ret = -1;
	int i;

	n = skip_type_mod(name);

	if (!strncmp(n, "struct", 6) && my_isblank(n[6])) {
		type->is_struct = 1;

		n += 6;
		while (my_isblank(*n))
			n++;
	}

	for (i = 0; i < ARRAY_SIZE(known_ptr_types); i++) {
		if (typecmp(n, known_ptr_types[i]))
			continue;

		type->is_ptr = 1;
		break;
	}

	if (n[0] == 'L' && n[1] == 'P' && strncmp(n, "LPARAM", 6))
		type->is_ptr = 1;

	// assume single word
	while (!my_isblank(*n) && !my_issep(*n))
		n++;

	while (1) {
		n1 = n;
		while (my_isblank(*n))
			n++;
		if (*n == '*') {
			type->is_ptr = 1;
			n++;
			continue;
		}
		break;
	}

	ret = n1 - name;
	type->name = strndup(name, ret);
	if (IS(type->name, "__VALIST") || IS(type->name, "va_list"))
		type->is_va_list = 1;
	if (IS(type->name, "VOID"))
		memcpy(type->name, "void", 4);

	return ret;
}

/* args are always expanded to 32bit */
static const char *map_reg(const char *reg)
{
	const char *regs_f[] = { "eax", "ebx", "ecx", "edx", "esi", "edi" };
	const char *regs_w[] = { "ax",  "bx",  "cx",  "dx",  "si",  "di" };
	const char *regs_b[] = { "al",  "bl",  "cl",  "dl" };
	int i;

	for (i = 0; i < ARRAY_SIZE(regs_w); i++)
		if (IS(reg, regs_w[i]))
			return regs_f[i];

	for (i = 0; i < ARRAY_SIZE(regs_b); i++)
		if (IS(reg, regs_b[i]))
			return regs_f[i];

	return reg;
}

static int check_struct_arg(struct parsed_proto_arg *arg)
{
	if (IS(arg->type.name, "POINT"))
		return 2 - 1;

	return 0;
}

static int parse_protostr(char *protostr, struct parsed_proto *pp);

static int parse_arg(char **p_, struct parsed_proto_arg *arg, int xarg)
{
	char buf[256];
	char *p = *p_;
	char *pe;
	int ret;

	arg->pp = calloc(1, sizeof(*arg->pp));
	my_assert_not(arg->pp, NULL);
	arg->pp->is_arg = 1;

	pe = p;
	while (1) {
		pe = strpbrk(pe, ",()");
		if (pe == NULL)
			return -1;
		if (*pe == ',' || *pe == ')')
			break;
		pe = strchr(pe, ')');
		if (pe == NULL)
			return -1;
		pe++;
	}

	if (pe - p > sizeof(buf) - 1)
		return -1;
	memcpy(buf, p, pe - p);
	buf[pe - p] = 0;

	ret = parse_protostr(buf, arg->pp);
	if (ret < 0)
		return -1;

	if (IS_START(arg->pp->name, "guess"))
		arg->pp->is_guessed = 1;

	// we don't use actual names right now...
	snprintf(arg->pp->name, sizeof(arg->pp->name), "a%d", xarg);

	if (!arg->type.is_struct)
		// we'll treat it as void * for non-calls
		arg->type.name = strdup("void *");
	arg->type.is_ptr = 1;

	p += ret;
	*p_ = p;
	return 0;
}

static int parse_protostr(char *protostr, struct parsed_proto *pp)
{
	struct parsed_proto_arg *arg;
	char regparm[16];
	char buf[256];
	char cconv[32];
	int is_retreg;
	char *p, *p1;
	int xarg = 0;
	int i, l;
	int ret;

	p = sskip(protostr);
	if (p[0] == '/' && p[1] == '/') {
		printf("%s:%d: commented out?\n", hdrfn, hdrfline);
		p = sskip(p + 2);
	}

	// allow start of line comment
	if (p[0] == '/' && p[1] == '*') {
		p = strstr(p + 2, "*/");
		if (p == NULL) {
			printf("%s:%d: multiline comments unsupported\n",
				hdrfn, hdrfline);
			return -1;
		}
		p = sskip(p + 2);
	}

	// we need remaining hints in comments, so strip / *
	for (p1 = p; p1[0] != 0 && p1[1] != 0; p1++) {
		if ((p1[0] == '/' && p1[1] == '*')
		 || (p1[0] == '*' && p1[1] == '/'))
			p1[0] = p1[1] = ' ';
	}

	if (!strncmp(p, "DECLSPEC_NORETURN ", 18)) {
		pp->is_noreturn = 1;
		p = sskip(p + 18);
	}

	for (i = 0; i < ARRAY_SIZE(ignored_keywords); i++) {
		l = strlen(ignored_keywords[i]);
		if (!strncmp(p, ignored_keywords[i], l) && my_isblank(p[l]))
			p = sskip(p + l + 1);
	}

	if (IS_START(p, "DECL_IMPORT ")) {
		pp->is_import = 1;
		p = sskip(p + 12);
	}

	ret = check_type(p, &pp->ret_type);
	if (ret <= 0) {
		printf("%s:%d:%zd: unhandled return in '%s'\n",
			hdrfn, hdrfline, (p - protostr) + 1, protostr);
		return -1;
	}
	p = sskip(p + ret);

	if (!strncmp(p, "noreturn ", 9)) {
		pp->is_noreturn = 1;
		p = sskip(p + 9);
	}

	if (!strchr(p, ')')) {
		p = next_idt(buf, sizeof(buf), p);
		p = sskip(p);
		if (!pp->is_arg && buf[0] == 0) {
			printf("%s:%d:%zd: var name is missing\n",
				hdrfn, hdrfline, (p - protostr) + 1);
			return -1;
		}
		strcpy(pp->name, buf);

		p1 = strchr(p, ']');
		if (p1 != NULL) {
			p = p1 + 1;
			pp->ret_type.is_array = 1;
		}
		return p - protostr;
	}

	pp->is_func = 1;

	if (*p == '(') {
		pp->is_fptr = 1;
		p = sskip(p + 1);
	}

	p = next_word(cconv, sizeof(cconv), p);
	p = sskip(p);
	if (cconv[0] == 0) {
		printf("%s:%d:%zd: cconv missing\n",
			hdrfn, hdrfline, (p - protostr) + 1);
		return -1;
	}
	if      (IS(cconv, "__cdecl"))
		pp->is_stdcall = 0;
	else if (IS(cconv, "__stdcall"))
		pp->is_stdcall = 1;
	else if (IS(cconv, "__fastcall")) {
		pp->is_fastcall = 1;
		pp->is_stdcall = 1; // sort of..
	}
	else if (IS(cconv, "__thiscall"))
		pp->is_stdcall = 1;
	else if (IS(cconv, "__userpurge"))
		pp->is_stdcall = 1; // IDA
	else if (IS(cconv, "__usercall"))
		pp->is_stdcall = 0; // IDA
	else if (IS(cconv, "__userstack")) {
		pp->is_stdcall = 0; // custom
		pp->is_userstack = 1;
	}
	else if (IS(cconv, "WINAPI") || IS(cconv, "PASCAL"))
		pp->is_stdcall = 1;
	else {
		printf("%s:%d:%zd: unhandled cconv: '%s'\n",
			hdrfn, hdrfline, (p - protostr) + 1, cconv);
		return -1;
	}

	if (pp->is_fptr) {
		if (*p != '*') {
			printf("%s:%d:%zd: '*' expected\n",
				hdrfn, hdrfline, (p - protostr) + 1);
			return -1;
		}
		p++;
		// XXX: skipping extra asterisks, for now
		while (*p == '*')
			p++;
		p = sskip(p);
	}

	p = next_idt(buf, sizeof(buf), p);
	p = sskip(p);
	if (buf[0] == 0) {
		//printf("%s:%d:%zd: func name missing\n",
		//	hdrfn, hdrfline, (p - protostr) + 1);
		//return -1;
	}
	strcpy(pp->name, buf);

	ret = get_regparm(regparm, sizeof(regparm), p, &is_retreg);
	if (ret > 0) {
		if (!IS(regparm, "eax") && !IS(regparm, "ax")
		 && !IS(regparm, "al") && !IS(regparm, "edx:eax"))
		{
			printf("%s:%d:%zd: bad regparm: %s\n",
				hdrfn, hdrfline, (p - protostr) + 1, regparm);
			return -1;
		}
		p += ret;
		p = sskip(p);
	}

	if (pp->is_fptr) {
		if (*p == '[') {
			// not really ret_type is array, but ohwell
			pp->ret_type.is_array = 1;
			p = strchr(p + 1, ']');
			if (p == NULL) {
				printf("%s:%d:%zd: ']' expected\n",
				 hdrfn, hdrfline, (p - protostr) + 1);
				return -1;
			}
			p = sskip(p + 1);
		}
		if (*p != ')') {
			printf("%s:%d:%zd: ')' expected\n",
				hdrfn, hdrfline, (p - protostr) + 1);
			return -1;
		}
		p = sskip(p + 1);
	}

	if (*p != '(') {
		printf("%s:%d:%zd: '(' expected, got '%c'\n",
				hdrfn, hdrfline, (p - protostr) + 1, *p);
		return -1;
	}
	p++;

	// check for x(void)
	p = sskip(p);
	if ((!strncmp(p, "void", 4) || !strncmp(p, "VOID", 4))
	   && *sskip(p + 4) == ')')
		p += 4;

	while (1) {
		p = sskip(p);
		if (*p == ')') {
			p++;
			break;
		}
		if (xarg > 0) {
			if (*p != ',') {
				printf("%s:%d:%zd: ',' expected\n",
				 hdrfn, hdrfline, (p - protostr) + 1);
				return -1;
			}
			p = sskip(p + 1);
		}

		if (!strncmp(p, "...", 3)) {
			pp->is_vararg = 1;
			p = sskip(p + 3);
			if (*p == ')') {
				p++;
				break;
			}
			printf("%s:%d:%zd: ')' expected\n",
				hdrfn, hdrfline, (p - protostr) + 1);
			return -1;
		}

		if (xarg >= ARRAY_SIZE(pp->arg)) {
			printf("%s:%d:%zd: too many args\n",
				hdrfn, hdrfline, (p - protostr) + 1);
			return -1;
		}

		arg = &pp->arg[xarg];
		xarg++;

		p1 = p;
		ret = check_type(p, &arg->type);
		if (ret <= 0) {
			printf("%s:%d:%zd: unhandled type for arg%d\n",
				hdrfn, hdrfline, (p - protostr) + 1, xarg);
			return -1;
		}
		p = sskip(p + ret);

		if (*p == '(' || arg->type.is_struct) {
			// func ptr or struct
			ret = parse_arg(&p1, arg, xarg);
			if (ret < 0) {
				printf("%s:%d:%zd: funcarg parse failed\n",
					hdrfn, hdrfline, p1 - protostr);
				return -1;
			}
			p = p1;
		}

		p = next_idt(buf, sizeof(buf), p);
		p = sskip(p);
#if 0
		if (buf[0] == 0) {
			printf("%s:%d:%zd: idt missing for arg%d\n",
				hdrfn, hdrfline, (p - protostr) + 1, xarg);
			return -1;
		}
#endif
		arg->reg = NULL;

		ret = get_regparm(regparm, sizeof(regparm), p, &is_retreg);
		if (ret > 0) {
			p += ret;
			p = sskip(p);

			arg->reg = strdup(map_reg(regparm));
			arg->type.is_retreg = is_retreg;
			pp->has_retreg |= is_retreg;
		}

		if (IS(arg->type.name, "float")
		      || IS(arg->type.name, "double"))
		{
			arg->type.is_float = 1;
		}

		if (!arg->type.is_ptr && (strstr(arg->type.name, "int64")
		      || IS(arg->type.name, "double")))
		{
			arg->type.is_64bit = 1;
			// hack..
			pp_copy_arg(&pp->arg[xarg], arg);
			arg = &pp->arg[xarg];
			xarg++;
			free(arg->type.name);
			arg->type.name = strdup("dummy");
		}

		ret = check_struct_arg(arg);
		if (ret > 0) {
			pp->has_structarg = 1;
			arg->type.is_struct = 1;
			free(arg->type.name);
			arg->type.name = strdup("int");
			for (l = 0; l < ret; l++) {
				pp_copy_arg(&pp->arg[xarg], arg);
				xarg++;
			}
		}
	}

	if (xarg > 0 && (IS(cconv, "__fastcall") || IS(cconv, "__thiscall"))) {
		if (pp->arg[0].reg != NULL) {
			printf("%s:%d: %s with arg1 spec %s?\n",
				hdrfn, hdrfline, cconv, pp->arg[0].reg);
		}
		pp->arg[0].reg = strdup("ecx");
	}

	if (xarg > 1 && IS(cconv, "__fastcall")) {
		if (pp->arg[1].reg != NULL) {
			printf("%s:%d: %s with arg2 spec %s?\n",
				hdrfn, hdrfline, cconv, pp->arg[1].reg);
		}
		pp->arg[1].reg = strdup("edx");
	}

	pp->argc = xarg;

	for (i = 0; i < pp->argc; i++) {
		if (pp->arg[i].reg == NULL)
			pp->argc_stack++;
		else
			pp->argc_reg++;
	}

	if (pp->argc == 1 && pp->arg[0].reg != NULL
	    && IS(pp->arg[0].reg, "ecx"))
	{
		pp->is_fastcall = 1;
	}
	else if (pp->argc_reg == 2
	  && pp->arg[0].reg != NULL && IS(pp->arg[0].reg, "ecx")
	  && pp->arg[1].reg != NULL && IS(pp->arg[1].reg, "edx"))
	{
		pp->is_fastcall = 1;
	}

	if (pp->is_vararg && (pp->is_stdcall || pp->is_fastcall)) {
		printf("%s:%d: vararg %s?\n", hdrfn, hdrfline, cconv);
		return -1;
	}

	return p - protostr;
}

static int pp_name_cmp(const void *p1, const void *p2)
{
	const struct parsed_proto *pp1 = p1, *pp2 = p2;
	return strcmp(pp1->name, pp2->name);
}

static int ps_name_cmp(const void *p1, const void *p2)
{
	const struct parsed_struct *ps1 = p1, *ps2 = p2;
	return strcmp(ps1->name, ps2->name);
}

// parsed struct cache
static struct parsed_struct *ps_cache;
static int ps_cache_size;
static int ps_cache_alloc;

static int struct_handler(FILE *fhdr, char *proto, int *line)
{
	struct parsed_struct *ps;
	char lstr[256], *p;
	int offset = 0;
	int m = 0;
	int ret;

	if (ps_cache_size >= ps_cache_alloc) {
		ps_cache_alloc = ps_cache_alloc * 2 + 64;
		ps_cache = realloc(ps_cache, ps_cache_alloc
				* sizeof(ps_cache[0]));
		my_assert_not(ps_cache, NULL);
		memset(ps_cache + ps_cache_size, 0,
			(ps_cache_alloc - ps_cache_size)
			 * sizeof(ps_cache[0]));
	}

	ps = &ps_cache[ps_cache_size++];
	ret = sscanf(proto, "struct %255s {", ps->name);
	if (ret != 1) {
		printf("%s:%d: struct parse failed\n", hdrfn, *line);
		return -1;
	}

	while (fgets(lstr, sizeof(lstr), fhdr))
	{
		(*line)++;

		p = sskip(lstr);
		if (p[0] == '/' && p[1] == '/')
			continue;
		if (p[0] == '}')
			break;

		if (m >= ARRAY_SIZE(ps->members)) {
			printf("%s:%d: too many struct members\n",
				hdrfn, *line);
			return -1;
		}

		hdrfline = *line;
		ret = parse_protostr(p, &ps->members[m].pp);
		if (ret < 0) {
			printf("%s:%d: struct member #%d/%02x "
				"doesn't parse\n", hdrfn, *line,
				m, offset);
			return -1;
		}
		ps->members[m].offset = offset;
		offset += 4;
		m++;
	}

	ps->member_count = m;

	return 0;
}

// parsed proto cache
static struct parsed_proto *pp_cache;
static int pp_cache_size;
static int pp_cache_alloc;

static int b_pp_c_handler(char *proto, const char *fname,
	int is_include, int is_osinc, int is_cinc)
{
	int ret;

	if (pp_cache_size >= pp_cache_alloc) {
		pp_cache_alloc = pp_cache_alloc * 2 + 64;
		pp_cache = realloc(pp_cache, pp_cache_alloc
				* sizeof(pp_cache[0]));
		my_assert_not(pp_cache, NULL);
		memset(pp_cache + pp_cache_size, 0,
			(pp_cache_alloc - pp_cache_size)
			 * sizeof(pp_cache[0]));
	}

	ret = parse_protostr(proto, &pp_cache[pp_cache_size]);
	if (ret < 0)
		return -1;

	pp_cache[pp_cache_size].is_include = is_include;
	pp_cache[pp_cache_size].is_osinc = is_osinc;
	pp_cache[pp_cache_size].is_cinc = is_cinc;
	pp_cache_size++;
	return 0;
}

static void build_caches(FILE *fhdr)
{
	long pos;
	int ret;

	pos = ftell(fhdr);
	rewind(fhdr);

	ret = do_protostrs(fhdr, hdrfn, 0);
	if (ret < 0)
		exit(1);

	qsort(pp_cache, pp_cache_size, sizeof(pp_cache[0]), pp_name_cmp);
	qsort(ps_cache, ps_cache_size, sizeof(ps_cache[0]), ps_name_cmp);
	fseek(fhdr, pos, SEEK_SET);
}

static const struct parsed_proto *proto_parse(FILE *fhdr, const char *sym,
	int quiet)
{
	const struct parsed_proto *pp_ret;
	struct parsed_proto pp_search;
	char *p;

	if (pp_cache == NULL)
		build_caches(fhdr);

	// ugh...
	if (sym[0] == '_' && !IS_START(sym, "__W"))
		sym++;

	strcpy(pp_search.name, sym);
	p = strchr(pp_search.name, '@');
	if (p != NULL)
		*p = 0;

	pp_ret = bsearch(&pp_search, pp_cache, pp_cache_size,
			sizeof(pp_cache[0]), pp_name_cmp);
	if (pp_ret == NULL && !quiet)
		printf("%s: sym '%s' is missing\n", hdrfn, sym);

	return pp_ret;
}

static const struct parsed_proto *proto_lookup_struct(FILE *fhdr,
	const char *type, int offset)
{
	struct parsed_struct ps_search, *ps;
	int m;

	if (pp_cache == NULL)
		build_caches(fhdr);
	if (ps_cache_size == 0)
		return NULL;

	while (my_isblank(*type))
		type++;
	if (!strncmp(type, "struct", 6) && my_isblank(type[6]))
		type += 7;

	if (sscanf(type, "%255s", ps_search.name) != 1)
		return NULL;

	ps = bsearch(&ps_search, ps_cache, ps_cache_size,
			sizeof(ps_cache[0]), ps_name_cmp);
	if (ps == NULL) {
		printf("%s: struct '%s' is missing\n",
			hdrfn, ps_search.name);
		return NULL;
	}

	for (m = 0; m < ps->member_count; m++) {
		if (ps->members[m].offset == offset)
			return &ps->members[m].pp;
	}

	return NULL;
}

static void pp_copy_arg(struct parsed_proto_arg *d,
	const struct parsed_proto_arg *s)
{
	memcpy(d, s, sizeof(*d));

	if (s->reg != NULL) {
		d->reg = strdup(s->reg);
		my_assert_not(d->reg, NULL);
	}
	if (s->type.name != NULL) {
		d->type.name = strdup(s->type.name);
		my_assert_not(d->type.name, NULL);
	}
	if (s->pp != NULL) {
		d->pp = malloc(sizeof(*d->pp));
		my_assert_not(d->pp, NULL);
		memcpy(d->pp, s->pp, sizeof(*d->pp));
	}
}

struct parsed_proto *proto_clone(const struct parsed_proto *pp_c)
{
	struct parsed_proto *pp;
	int i;

	pp = malloc(sizeof(*pp));
	my_assert_not(pp, NULL);
	memcpy(pp, pp_c, sizeof(*pp)); // lazy..

	// do the actual deep copy..
	for (i = 0; i < pp_c->argc; i++)
		pp_copy_arg(&pp->arg[i], &pp_c->arg[i]);
	if (pp_c->ret_type.name != NULL)
		pp->ret_type.name = strdup(pp_c->ret_type.name);

	return pp;
}


static inline int pp_cmp_func(const struct parsed_proto *pp1,
  const struct parsed_proto *pp2)
{
  int i;

  if (pp1->argc != pp2->argc || pp1->argc_reg != pp2->argc_reg)
    return 1;
  if (pp1->is_stdcall != pp2->is_stdcall)
    return 1;

  // because of poor void return detection, return is not
  // checked for now to avoid heaps of false positives

  for (i = 0; i < pp1->argc; i++) {
    if ((pp1->arg[i].reg != NULL) != (pp2->arg[i].reg != NULL))
      return 1;

    if ((pp1->arg[i].reg != NULL)
      && !IS(pp1->arg[i].reg, pp2->arg[i].reg))
    {
      return 1;
    }
  }

  return 0;
}

static inline int pp_compatible_func(
  const struct parsed_proto *pp_site,
  const struct parsed_proto *pp_callee)
{
  if (pp_cmp_func(pp_site, pp_callee) == 0)
    return 1;

  if (pp_site->argc_stack == 0 && pp_site->is_fastcall
      && pp_callee->argc_stack == 0
      && (pp_callee->is_fastcall || pp_callee->argc_reg == 0)
      && pp_site->argc_reg > pp_callee->argc_reg)
    /* fascall compatible callee doesn't use all args -> ok */
    return 1;

  return 0;
}

static inline void pp_print(char *buf, size_t buf_size,
  const struct parsed_proto *pp)
{
  size_t l;
  int i;

  snprintf(buf, buf_size, "%s %s(", pp->ret_type.name, pp->name);
  l = strlen(buf);

  for (i = 0; i < pp->argc_reg; i++) {
    snprintf(buf + l, buf_size - l, "%s%s",
      i == 0 ? "" : ", ", pp->arg[i].reg);
    l = strlen(buf);
  }
  if (pp->argc_stack > 0) {
    snprintf(buf + l, buf_size - l, "%s{%d stack}",
      i == 0 ? "" : ", ", pp->argc_stack);
    l = strlen(buf);
  }
  snprintf(buf + l, buf_size - l, ")");
}

static inline void proto_release(struct parsed_proto *pp)
{
	int i;

	for (i = 0; i < pp->argc; i++) {
		free(pp->arg[i].reg);
		free(pp->arg[i].type.name);
		free(pp->arg[i].pp);
		free(pp->arg[i].push_refs);
	}
	if (pp->ret_type.name != NULL)
		free(pp->ret_type.name);
	free(pp);

	(void)proto_lookup_struct;
}
