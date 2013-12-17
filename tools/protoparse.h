
struct parsed_proto;

struct parsed_proto_arg {
	char *reg;
	char *type;
	struct parsed_proto *fptr;
	void *datap;
};

struct parsed_proto {
	char name[256];
	char *ret_type;
	struct parsed_proto_arg arg[16];
	int argc;
	int argc_stack;
	int argc_reg;
	unsigned int is_func:1;
	unsigned int is_stdcall:1;
	unsigned int is_fptr:1;
	unsigned int is_array:1;
};

static const char *hdrfn;
static int hdrfline = 0;

static int find_protostr(char *dst, size_t dlen, FILE *fhdr,
	const char *fname, const char *sym_)
{
	const char *sym = sym_;
	const char *finc_name;
	FILE *finc;
	int symlen;
	int line = 0;
	int ret;
	char *p;

	if (sym[0] == '_' && strncmp(fname, "stdc", 4) == 0)
		sym++;
	symlen = strlen(sym);

	rewind(fhdr);

	while (fgets(dst, dlen, fhdr))
	{
		line++;
		if (strncmp(dst, "//#include ", 11) == 0) {
			finc_name = dst + 11;
			p = strpbrk(finc_name, "\r\n ");
			if (p != NULL)
				*p = 0;

			finc = fopen(finc_name, "r");
			if (finc == NULL) {
				printf("%s:%d: can't open '%s'\n",
					fname, line, finc_name);
				continue;
			}
			ret = find_protostr(dst, dlen, finc,
				finc_name, sym_);
			fclose(finc);
			if (ret == 0)
				break;
			continue;
		}
		if (strncmp(sskip(dst), "//", 2) == 0)
			continue;

		p = strstr(dst, sym);
		if (p != NULL && p > dst
		   && (my_isblank(p[-1]) || my_issep(p[-1]))
		   && (my_isblank(p[symlen]) || my_issep(p[symlen])))
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
static const char *known_type_mod[] = {
	"const",
	"signed",
	"unsigned",
};

static const char *known_types[] = {
	"void *",
	"char *",
	"FILE *",
	"int *",
	"__int8 *",
	"__int16 *",
	"char",
	"__int8",
	"__int16",
	"__int32",
	"int",
	"bool",
	"void",
	"BYTE",
	"WORD",
	"BOOL",
	"DWORD",
	"_DWORD",
	"HMODULE",
	"HANDLE",
	"HWND",
	"LANGID",
	"LPCSTR",
	"size_t",
};

// returns ptr to char after type ends
static const char *typecmp(const char *n, const char *t)
{
	for (; *t != 0; n++, t++) {
		while (n[0] == ' ' && (n[1] == ' ' || n[1] == '*'))
			n++;
		while (t[0] == ' ' && (t[1] == ' ' || t[1] == '*'))
			t++;
		if (*n != *t)
			return NULL;
	}

	return n;
}

static char *check_type(const char *name, int *len_out)
{
	const char *n = name, *n1;
	int len;
	int i;

	*len_out = 0;

	for (i = 0; i < ARRAY_SIZE(known_type_mod); i++) {
		len = strlen(known_type_mod[i]);
		if (strncmp(n, known_type_mod[i], len) != 0)
			continue;

		n += len;
		while (my_isblank(*n))
			n++;
		i = 0;
	}

	for (i = 0; i < ARRAY_SIZE(known_types); i++) {
		n1 = typecmp(n, known_types[i]);
		if (n1 == NULL)
			continue;

		*len_out = n1 - name;
		return strndup(name, *len_out);
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
	struct parsed_proto_arg *arg;
	char regparm[16];
	char buf[256];
	char cconv[32];
	char *kt;
	int xarg = 0;
	char *p, *p1;
	int ret;
	int i;

	p = sskip(protostr);
	if (p[0] == '/' && p[1] == '/') {
		printf("%s:%d: commented out?\n", hdrfn, hdrfline);
		p = sskip(p + 2);
	}

	// strip unneeded stuff
	for (p1 = p; p1[0] != 0 && p1[1] != 0; p1++) {
		if ((p1[0] == '/' && p1[1] == '*')
		 || (p1[0] == '*' && p1[1] == '/'))
			p1[0] = p1[1] = ' ';
	}

	if (strncmp(p, "extern ", 7) == 0)
		p = sskip(p + 7);
	if (strncmp(p, "WINBASEAPI ", 11) == 0)
		p = sskip(p + 11);

	kt = check_type(p, &ret);
	if (kt == NULL) {
		printf("%s:%d:%ld: unhandled return in '%s'\n",
			hdrfn, hdrfline, (p - protostr) + 1, protostr);
		return -1;
	}
	pp->ret_type = kt;
	p = sskip(p + ret);

	if (!strchr(p, ')')) {
		p = next_idt(buf, sizeof(buf), p);
		p = sskip(p);
		if (buf[0] == 0) {
			printf("%s:%d:%ld: var name missing\n",
				hdrfn, hdrfline, (p - protostr) + 1);
			return -1;
		}
		strcpy(pp->name, buf);

		p1 = strchr(p, ']');
		if (p1 != NULL) {
			p = p1 + 1;
			pp->is_array = 1;
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
		printf("%s:%d:%ld: cconv missing\n",
			hdrfn, hdrfline, (p - protostr) + 1);
		return -1;
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
	else if (IS(cconv, "WINAPI"))
		pp->is_stdcall = 1;
	else {
		printf("%s:%d:%ld: unhandled cconv: '%s'\n",
			hdrfn, hdrfline, (p - protostr) + 1, cconv);
		return -1;
	}

	if (pp->is_fptr) {
		if (*p != '*') {
			printf("%s:%d:%ld: '*' expected\n",
				hdrfn, hdrfline, (p - protostr) + 1);
			return -1;
		}
		p = sskip(p + 1);
	}

	p = next_idt(buf, sizeof(buf), p);
	p = sskip(p);
	if (buf[0] == 0) {
		printf("%s:%d:%ld: func name missing\n",
			hdrfn, hdrfline, (p - protostr) + 1);
		return -1;
	}
	strcpy(pp->name, buf);

	ret = get_regparm(regparm, sizeof(regparm), p);
	if (ret > 0) {
		if (!IS(regparm, "eax") && !IS(regparm, "ax")
		 && !IS(regparm, "al"))
		{
			printf("%s:%d:%ld: bad regparm: %s\n",
				hdrfn, hdrfline, (p - protostr) + 1, regparm);
			return -1;
		}
		p += ret;
		p = sskip(p);
	}

	if (pp->is_fptr) {
		if (*p != ')') {
			printf("%s:%d:%ld: ')' expected\n",
				hdrfn, hdrfline, (p - protostr) + 1);
			return -1;
		}
		p = sskip(p + 1);
	}

	if (*p != '(') {
		printf("%s:%d:%ld: '(' expected, got '%c'\n",
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
		if (*p == ',')
			p = sskip(p + 1);

		arg = &pp->arg[xarg];
		xarg++;

		p1 = p;
		kt = check_type(p, &ret);
		if (kt == NULL) {
			printf("%s:%d:%ld: unhandled type for arg%d\n",
				hdrfn, hdrfline, (p - protostr) + 1, xarg);
			return -1;
		}
		arg->type = kt;
		p = sskip(p + ret);

		if (*p == '(') {
			// func ptr
			arg->fptr = calloc(1, sizeof(*arg->fptr));
			ret = parse_protostr(p1, arg->fptr);
			if (ret < 0) {
				printf("%s:%d:%ld: funcarg parse failed\n",
					hdrfn, hdrfline, p1 - protostr);
				return -1;
			}
			// we'll treat it as void * for non-calls
			arg->type = "void *";

			p = p1 + ret;
		}

		p = next_idt(buf, sizeof(buf), p);
		p = sskip(p);
#if 0
		if (buf[0] == 0) {
			printf("%s:%d:%ld: idt missing for arg%d\n",
				hdrfn, hdrfline, (p - protostr) + 1, xarg);
			return -1;
		}
#endif
		arg->reg = NULL;

		ret = get_regparm(regparm, sizeof(regparm), p);
		if (ret > 0) {
			p += ret;
			p = sskip(p);

			arg->reg = strdup(map_reg(regparm));
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

	return p - protostr;
}

static int proto_parse(FILE *fhdr, const char *sym, struct parsed_proto *pp)
{
	char protostr[256];
	int ret;

	memset(pp, 0, sizeof(*pp));

	ret = find_protostr(protostr, sizeof(protostr), fhdr, hdrfn, sym);
	if (ret != 0) {
		printf("%s: sym '%s' is missing\n", hdrfn, sym);
		return ret;
	}

	return parse_protostr(protostr, pp) < 0 ? -1 : 0;
}

static void proto_release(struct parsed_proto *pp)
{
	int i;

	for (i = 0; i < pp->argc; i++) {
		if (pp->arg[i].reg != NULL)
			free(pp->arg[i].reg);
		if (pp->arg[i].type != NULL)
			free(pp->arg[i].type);
		if (pp->arg[i].fptr != NULL)
			free(pp->arg[i].fptr);
	}
	if (pp->ret_type != NULL)
		free(pp->ret_type);
}
