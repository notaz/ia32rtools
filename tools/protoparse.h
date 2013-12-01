
struct parsed_proto {
	struct {
		char *reg;
		const char *type;
		void *datap;
	} arg[16];
	const char *ret_type;
	int is_stdcall;
	int argc;
	int argc_stack;
	int argc_reg;
};

static const char *hdrfn;
static int hdrfline = 0;

static int find_protostr(char *dst, size_t dlen, FILE *fhdr, const char *sym)
{
	int line = 0;
	char *p;

	rewind(fhdr);

	while (fgets(dst, dlen, fhdr))
	{
		line++;
		if (strstr(dst, sym) != NULL)
			break;
	}
	hdrfline = line;

	if (feof(fhdr))
		return -1;

	p = dst + strlen(dst);
	for (p--; p > dst && my_isblank(*p); --p)
		*p = 0;

	return 0;
}

static int get_regparm(char *dst, size_t dlen, char *p)
{
	int i, o;

	if (*p != '<')
		return 0;

	for (o = 0, i = 1; o < dlen; i++) {
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
static const char *known_types[] = {
	"const void *",
	"void *",
	"char *",
	"FILE *",
	"int *",
	"unsigned __int8",
	"unsigned __int16",
	"unsigned int",
	"signed int",
	"char",
	"__int8",
	"__int16",
	"int",
	"bool",
	"void",
	"BYTE",
	"WORD",
	"DWORD",
	"_DWORD",
	"HMODULE",
	"HANDLE",
	"HWND",
	"LPCSTR",
	"size_t",
};

static const char *check_type(const char *name)
{
	int i, l;

	for (i = 0; i < ARRAY_SIZE(known_types); i++) {
		l = strlen(known_types[i]);
		if (strncmp(known_types[i], name, l) == 0)
			return known_types[i];
	}

	return NULL;
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

static int parse_protostr(char *protostr, struct parsed_proto *pp)
{
	char regparm[16];
	char buf[256];
	char cconv[32];
	const char *kt;
	int xarg = 0;
	int ret;
	char *p;
	int i;

	p = protostr;
	if (p[0] == '/' && p[1] == '/') {
		//printf("warning: decl for sym '%s' is commented out\n", sym);
		p = sskip(p + 2);
	}

	kt = check_type(p);
	if (kt == NULL) {
		printf("%s:%d:%ld: unhandled return in '%s'\n",
			hdrfn, hdrfline, (p - protostr) + 1, protostr);
		return 1;
	}
	pp->ret_type = kt;
	p += strlen(kt);
	p = sskip(p);

	p = next_word(cconv, sizeof(cconv), p);
	p = sskip(p);
	if (cconv[0] == 0) {
		printf("%s:%d:%ld: cconv missing\n",
			hdrfn, hdrfline, (p - protostr) + 1);
		return 1;
	}
	if      (IS(cconv, "__cdecl"))
		pp->is_stdcall = 0;
	else if (IS(cconv, "__stdcall"))
		pp->is_stdcall = 1;
	else if (IS(cconv, "__fastcall"))
		pp->is_stdcall = 1;
	else if (IS(cconv, "__thiscall"))
		pp->is_stdcall = 1;
	else if (IS(cconv, "__userpurge"))
		pp->is_stdcall = 1; // in all cases seen..
	else if (IS(cconv, "__usercall"))
		pp->is_stdcall = 0; // ..or is it?
	else {
		printf("%s:%d:%ld: unhandled cconv: '%s'\n",
			hdrfn, hdrfline, (p - protostr) + 1, cconv);
		return 1;
	}

	p = next_idt(buf, sizeof(buf), p);
	p = sskip(p);
	if (buf[0] == 0) {
		printf("%s:%d:%ld: func name missing\n",
				hdrfn, hdrfline, (p - protostr) + 1);
		return 1;
	}

	ret = get_regparm(regparm, sizeof(regparm), p);
	if (ret > 0) {
		if (!IS(regparm, "eax") && !IS(regparm, "ax")
		 && !IS(regparm, "al"))
		{
			printf("%s:%d:%ld: bad regparm: %s\n",
				hdrfn, hdrfline, (p - protostr) + 1, regparm);
			return 1;
		}
		p += ret;
		p = sskip(p);
	}

	if (*p != '(') {
		printf("%s:%d:%ld: '(' expected, got '%c'\n",
				hdrfn, hdrfline, (p - protostr) + 1, *p);
		return 1;
	}
	p++;

	while (1) {
		p = sskip(p);
		if (*p == ')')
			break;
		if (*p == ',')
			p = sskip(p + 1);

		xarg++;

		kt = check_type(p);
		if (kt == NULL) {
			printf("%s:%d:%ld: unhandled type for arg%d\n",
				hdrfn, hdrfline, (p - protostr) + 1, xarg);
			return 1;
		}
		pp->arg[xarg - 1].type = kt;
		p += strlen(kt);
		p = sskip(p);

		p = next_idt(buf, sizeof(buf), p);
		p = sskip(p);
#if 0
		if (buf[0] == 0) {
			printf("%s:%d:%ld: idt missing for arg%d\n",
				hdrfn, hdrfline, (p - protostr) + 1, xarg);
			return 1;
		}
#endif
		pp->arg[xarg - 1].reg = NULL;

		ret = get_regparm(regparm, sizeof(regparm), p);
		if (ret > 0) {
			p += ret;
			p = sskip(p);

			pp->arg[xarg - 1].reg = strdup(map_reg(regparm));
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

	return 0;
}

static int proto_parse(FILE *fhdr, const char *sym, struct parsed_proto *pp)
{
	char protostr[256];
	int ret;

	memset(pp, 0, sizeof(*pp));

	ret = find_protostr(protostr, sizeof(protostr), fhdr, sym);
	if (ret != 0) {
		printf("%s: sym '%s' is missing\n", hdrfn, sym);
		return ret;
	}

	return parse_protostr(protostr, pp);
}

static void proto_release(struct parsed_proto *pp)
{
	int i;

	for (i = 0; i < pp->argc; i++) {
		if (pp->arg[i].reg == NULL)
			free(pp->arg[i].reg);
	}
}
