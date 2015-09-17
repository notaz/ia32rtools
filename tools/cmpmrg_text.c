/*
 * ia32rtools
 * (C) notaz, 2013,2014
 *
 * This work is licensed under the terms of 3-clause BSD license.
 * See COPYING file in the top-level directory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/coff.h>
#include <assert.h>
#include <stdint.h>

#include "my_assert.h"

/* http://www.delorie.com/djgpp/doc/coff/ */

typedef struct {
  unsigned short f_magic;         /* magic number             */
  unsigned short f_nscns;         /* number of sections       */
  unsigned int   f_timdat;        /* time & date stamp        */
  unsigned int   f_symptr;        /* file pointer to symtab   */
  unsigned int   f_nsyms;         /* number of symtab entries */
  unsigned short f_opthdr;        /* sizeof(optional hdr)     */
  unsigned short f_flags;         /* flags                    */
} FILHDR;

typedef struct {
  unsigned short magic;          /* type of file                         */
  unsigned short vstamp;         /* version stamp                        */
  unsigned int   tsize;          /* text size in bytes, padded to FW bdry*/
  unsigned int   dsize;          /* initialized data    "  "             */
  unsigned int   bsize;          /* uninitialized data  "  "             */
  unsigned int   entry;          /* entry pt.                            */
  unsigned int   text_start;     /* base of text used for this file      */
  unsigned int   data_start;     /* base of data used for this file      */
} AOUTHDR;

typedef struct {
  char           s_name[8];  /* section name                     */
  unsigned int   s_paddr;    /* physical address, aliased s_nlib */
  unsigned int   s_vaddr;    /* virtual address                  */
  unsigned int   s_size;     /* section size                     */
  unsigned int   s_scnptr;   /* file ptr to raw data for section */
  unsigned int   s_relptr;   /* file ptr to relocation           */
  unsigned int   s_lnnoptr;  /* file ptr to line numbers         */
  unsigned short s_nreloc;   /* number of relocation entries     */
  unsigned short s_nlnno;    /* number of line number entries    */
  unsigned int   s_flags;    /* flags                            */
} SCNHDR;

typedef struct {
  unsigned int  r_vaddr;   /* address of relocation      */
  unsigned int  r_symndx;  /* symbol we're adjusting for */
  unsigned short r_type;    /* type of relocation         */
} __attribute__((packed)) RELOC;

typedef struct {
  union {
    char e_name[E_SYMNMLEN];
    struct {
      unsigned int e_zeroes;
      unsigned int e_offset;
    } e;
  } e;
  unsigned int e_value;
  short e_scnum;
  unsigned short e_type;
  unsigned char e_sclass;
  unsigned char e_numaux;
} __attribute__((packed)) SYMENT;

#define C_EXT 2

struct my_symtab {
  unsigned int addr;
  //unsigned int fpos; // for patching
  unsigned int is_text:1;
  char *name;
};

struct my_sect_info {
	long scnhdr_fofs;
	long sect_fofs;
	long reloc_fofs;
	uint8_t *data;
	long size;
	RELOC *relocs;
	long reloc_cnt;
};

static int symt_cmp(const void *p1_, const void *p2_)
{
	const struct my_symtab *p1 = p1_, *p2 = p2_;
	return p1->addr - p2->addr;
}

void parse_headers(FILE *f, unsigned int *base_out,
	struct my_sect_info *sect_i,
	struct my_symtab **symtab_out, long *sym_cnt,
	struct my_symtab **raw_symtab_out, long *raw_sym_cnt)
{
	struct my_symtab *symt_txt = NULL;
	struct my_symtab *symt_all = NULL;
	char *stringtab = NULL;
	unsigned int base = 0;
	int text_scnum = 0;
	long filesize;
	char symname[9];
	long opthdr_pos;
	long reloc_size;
	FILHDR hdr;
	AOUTHDR opthdr;
	SCNHDR scnhdr;
	SYMENT syment;
	int i, s, val;
	int ret;
	
	ret = fseek(f, 0, SEEK_END);
	my_assert(ret, 0);

	filesize = ftell(f);

	ret = fseek(f, 0, SEEK_SET);
	my_assert(ret, 0);

	ret = fread(&hdr, 1, sizeof(hdr), f);
	my_assert(ret, sizeof(hdr));

	if (hdr.f_magic == 0x5a4d) // MZ
	{
		ret = fseek(f, 0x3c, SEEK_SET);
		my_assert(ret, 0);
		ret = fread(&val, 1, sizeof(val), f);
		my_assert(ret, sizeof(val));

		ret = fseek(f, val, SEEK_SET);
		my_assert(ret, 0);
		ret = fread(&val, 1, sizeof(val), f);
		my_assert(ret, sizeof(val));
		my_assert(val, 0x4550); // PE

		// should be COFF now
		ret = fread(&hdr, 1, sizeof(hdr), f);
		my_assert(ret, sizeof(hdr));
	}

	my_assert(hdr.f_magic, COFF_I386MAGIC);

	if (hdr.f_opthdr != 0)
	{
		opthdr_pos = ftell(f);

		if (hdr.f_opthdr < sizeof(opthdr))
			my_assert(1, 0);

		ret = fread(&opthdr, 1, sizeof(opthdr), f);
		my_assert(ret, sizeof(opthdr));
		my_assert(opthdr.magic, COFF_ZMAGIC);

		//printf("text_start: %x\n", opthdr.text_start);

		if (hdr.f_opthdr > sizeof(opthdr)) {
			ret = fread(&base, 1, sizeof(base), f);
			my_assert(ret, sizeof(base));
			//printf("base: %x\n", base);
		}
		ret = fseek(f, opthdr_pos + hdr.f_opthdr, SEEK_SET);
		my_assert(ret, 0);
	}

	// note: assuming first non-empty one is .text ..
	for (s = 0; s < hdr.f_nscns; s++) {
		sect_i->scnhdr_fofs = ftell(f);

		ret = fread(&scnhdr, 1, sizeof(scnhdr), f);
		my_assert(ret, sizeof(scnhdr));

		if (scnhdr.s_size != 0) {
			text_scnum = s + 1;
			break;
		}
	}
	my_assert(s < hdr.f_nscns, 1);

#if 0
	printf("f_nsyms:  %x\n", hdr.f_nsyms);
	printf("s_name:   '%s'\n", scnhdr.s_name);
	printf("s_vaddr:  %x\n", scnhdr.s_vaddr);
	printf("s_size:   %x\n", scnhdr.s_size);
	//printf("s_scnptr: %x\n", scnhdr.s_scnptr);
	printf("s_nreloc: %x\n", scnhdr.s_nreloc);
	printf("--\n");
#endif

	ret = fseek(f, scnhdr.s_scnptr, SEEK_SET);
	my_assert(ret, 0);

	sect_i->data = malloc(scnhdr.s_size);
	my_assert_not(sect_i->data, NULL);
	ret = fread(sect_i->data, 1, scnhdr.s_size, f);
	my_assert(ret, scnhdr.s_size);

	sect_i->sect_fofs = scnhdr.s_scnptr;
	sect_i->size = scnhdr.s_size;

	// relocs
	ret = fseek(f, scnhdr.s_relptr, SEEK_SET);
	my_assert(ret, 0);

	reloc_size = scnhdr.s_nreloc * sizeof(sect_i->relocs[0]);
	sect_i->relocs = malloc(reloc_size + 1);
	my_assert_not(sect_i->relocs, NULL);
	ret = fread(sect_i->relocs, 1, reloc_size, f);
	my_assert(ret, reloc_size);

	sect_i->reloc_cnt = scnhdr.s_nreloc;
	sect_i->reloc_fofs = scnhdr.s_relptr;

	if (base != 0 && base_out != NULL)
		*base_out = base + scnhdr.s_vaddr;

	if (symtab_out == NULL || sym_cnt == NULL)
		return;

	// symtab
	if (hdr.f_nsyms != 0) {
		symname[8] = 0;

		symt_txt = malloc(hdr.f_nsyms * sizeof(symt_txt[0]) + 1);
		my_assert_not(symt_txt, NULL);
		symt_all = malloc(hdr.f_nsyms * sizeof(symt_all[0]) + 1);
		my_assert_not(symt_all, NULL);

		ret = fseek(f, hdr.f_symptr
				+ hdr.f_nsyms * sizeof(syment), SEEK_SET);
		my_assert(ret, 0);
		ret = fread(&i, 1, sizeof(i), f);
		my_assert(ret, sizeof(i));
		my_assert((unsigned int)i < filesize, 1);

		stringtab = malloc(i);
		my_assert_not(stringtab, NULL);
		memset(stringtab, 0, 4);
		ret = fread(stringtab + 4, 1, i - 4, f);
		my_assert(ret, i - 4);

		ret = fseek(f, hdr.f_symptr, SEEK_SET);
		my_assert(ret, 0);
	}

	for (i = s = 0; i < hdr.f_nsyms; i++) {
		//long pos = ftell(f);

		ret = fread(&syment, 1, sizeof(syment), f);
		my_assert(ret, sizeof(syment));

		strncpy(symname, syment.e.e_name, 8);
		//printf("%3d %2d %08x '%s'\n", syment.e_sclass,
		//	syment.e_scnum, syment.e_value, symname);

		symt_all[i].addr = syment.e_value;
		//symt_all[i].fpos = pos;
		if (syment.e.e.e_zeroes == 0)
			symt_all[i].name = stringtab + syment.e.e.e_offset;
		else
			symt_all[i].name = strdup(symname);

		symt_all[i].is_text = (syment.e_scnum == text_scnum);
		if (symt_all[i].is_text && syment.e_sclass == C_EXT) {
			symt_txt[s] = symt_all[i];
			s++;
		}

		if (syment.e_numaux) {
			ret = fseek(f, syment.e_numaux * sizeof(syment),
				    SEEK_CUR);
			my_assert(ret, 0);
			i += syment.e_numaux;
		}
	}

	if (symt_txt != NULL)
		qsort(symt_txt, s, sizeof(symt_txt[0]), symt_cmp);

	*sym_cnt = s;
	*symtab_out = symt_txt;
	*raw_sym_cnt = i;
	*raw_symtab_out = symt_all;
}

static int try_align(uint8_t *d_obj, uint8_t *d_exe, int maxlen)
{
	static const uint8_t aligns[8][7] = {
		{ }, // [0] not used
		{ 0x90 }, // [1] nop
		{ 0x8b, 0xff }, // mov edi, edi
		{ 0x8d, 0x49, 0x00 }, // lea ecx, [ecx]
		{ 0x8d, 0x64, 0x24, 0x00 }, // lea
		{ 0x05, 0x00, 0x00, 0x00, 0x00 }, // add eax, 0
		{ 0x8d, 0x9b, 0x00, 0x00, 0x00, 0x00 },
		{ 0x8d, 0xa4, 0x24, 0x00, 0x00, 0x00, 0x00 },
	};
	int j = 0;
	int len;
	int i;

	// check exe for common pad/align patterns
	for (i = 0; i < maxlen; i++)
		if (d_exe[i] != 0xcc)
			break;

	while (j < 8) {
		for (j = 1; j < 8; j++) {
			if (maxlen - i < j) {
				j = 8;
				break;
			}
			if (memcmp(&d_exe[i], aligns[j], j) == 0) {
				i += j;
				break;
			}
		}
	}
	if (i == 0)
		return 0;

	// now check the obj
	for (j = 0, len = i; len > 0; )
	{
		i = len;
		if (i > 7)
			i = 7;

		if (memcmp(d_obj, aligns[i], i) != 0)
			break;

		memcpy(d_obj, d_exe, i);
		j += i;

		len -= i;
		d_obj += i;
		d_exe += i;
	}

	return j;
}

struct equiv_opcode {
	signed char len;
	signed char ofs;
	unsigned short cmp_rm:1;
	unsigned short simple:1;
	uint8_t v_masm[8];
	uint8_t v_masm_mask[8];
	uint8_t v_msvc[8];
	uint8_t v_msvc_mask[8];
} equiv_ops[] = {
	// cmp    $0x11,%ax
	{ 4, -1, 0, 0,
	 { 0x66,0x83,0xf8,0x03 }, { 0xff,0xff,0xff,0x00 },
	 { 0x66,0x3d,0x03,0x00 }, { 0xff,0xff,0x00,0xff }, },
	// lea    -0x1(%ebx,%eax,1),%esi // op mod/rm sib offs
	// mov, test, imm grp 1
	{ 3, -2, 1, 0,
	 { 0x8d,0x74,0x03 }, { 0xf0,0x07,0xc0 },
	 { 0x8d,0x74,0x18 }, { 0xf0,0x07,0xc0 }, },
	// movzbl 0x58f24a(%eax,%ecx,1),%eax
	{ 4, -3, 1, 0,
	 { 0x0f,0xb6,0x84,0x08 }, { 0xff,0xff,0x07,0xc0 },
	 { 0x0f,0xb6,0x84,0x01 }, { 0xff,0xff,0x07,0xc0 }, },
	// inc/dec
	{ 3, -2, 1, 0,
	 { 0xfe,0x4c,0x03 }, { 0xfe,0xff,0xc0 },
	 { 0xfe,0x4c,0x18 }, { 0xfe,0xff,0xc0 }, },
	// cmp
	{ 3, -2, 1, 0,
	 { 0x38,0x0c,0x0c }, { 0xff,0xff,0xc0 },
	 { 0x38,0x0c,0x30 }, { 0xff,0xff,0xc0 }, },
	// test   %dl,%bl
	{ 2, -1, 1, 0,
	 { 0x84,0xd3 }, { 0xfe,0xc0 },
	 { 0x84,0xda }, { 0xfe,0xc0 }, },
	// cmp	  r,r/m vs rm/r
	{ 2, 0, 1, 0,
	 { 0x3a,0xca }, { 0xff,0xc0 },
	 { 0x38,0xd1 }, { 0xff,0xc0 }, },
	// rep + 66 prefix
	{ 2, 0, 0, 0,
	 { 0xf3,0x66 }, { 0xfe,0xff },
	 { 0x66,0xf3 }, { 0xff,0xfe }, },
	// fadd   st, st(0) vs st(0), st
	{ 2, 0, 0, 0,
	 { 0xd8,0xc0 }, { 0xff,0xf7 },
	 { 0xdc,0xc0 }, { 0xff,0xf7 }, },
	// [esp] vs [esp+0]
	{ 4, -1, 0, 0,
	 { 0x00,0x04,0x24,0x90 }, { 0x00,0xc7,0xff,0xff },
	 { 0x00,0x44,0x24,0x00 }, { 0x00,0xc7,0xff,0xff }, },
	{ 5, -1, 0, 0,
	 { 0x00,0x04,0x24,0x00,0x90 }, { 0x00,0xc7,0xff,0x00,0xff },
	 { 0x00,0x44,0x24,0x00,0x00 }, { 0x00,0xc7,0xff,0xff,0x00 }, },
	{ 8, -1, 0, 0,
	 { 0x00,0x04,0x24,0x00,0x00,0x00,0x00,0x90 }, { 0x00,0xc7,0xff,0x00,0x00,0x00,0x00,0xff },
	 { 0x00,0x44,0x24,0x00,0x00,0x00,0x00,0x00 }, { 0x00,0xc7,0xff,0xff,0x00,0x00,0x00,0x00 }, },

        // various align insns/fillups
	{ 2, -1, 0, 0,
	 { 0x8b,0xff }, { 0xff,0xff },
	 { 0x8b,0xc0 }, { 0xff,0xff }, },
	{ 2, 0, 0, 1,
	 { 0x00,0x00 }, { 0x00,0x00 },
	 { 0x8b,0xc0 }, { 0xff,0xff }, },
	{ 3, 0, 0, 1,
	 { 0x00,0x00,0x00 }, { 0x50,0x00,0x00 },
	 { 0x2e,0x8b,0xc0 }, { 0xff,0xff,0xff }, },

	// broad filters (may take too much..)
	// testb  $0x4,0x1d(%esi,%eax,1)
	// movb, push, ..
	{ 3, -2, 1, 0,
	 { 0xf6,0x44,0x06 }, { 0x00,0x07,0xc0 },
	 { 0xf6,0x44,0x30 }, { 0x00,0x07,0xc0 }, },
};

static int cmp_mask(uint8_t *d, uint8_t *expect, uint8_t *mask, int len)
{
	int i;

	for (i = 0; i < len; i++)
		if ((d[i] & mask[i]) != (expect[i] & mask[i]))
			return 1;

	return 0;
}

static int check_equiv(uint8_t *d_obj, uint8_t *d_exe, int maxlen)
{
	uint8_t vo, ve, vo2, ve2;
	int i, jo, je;
	int len, ofs;

	for (i = 0; i < sizeof(equiv_ops) / sizeof(equiv_ops[0]); i++)
	{
		struct equiv_opcode *op = &equiv_ops[i];

		len = op->len;
		if (maxlen < len)
			continue;

		ofs = op->ofs;
		if (cmp_mask(d_obj + ofs, op->v_masm,
			     op->v_masm_mask, len))
			continue;
		if (cmp_mask(d_exe + ofs, op->v_msvc,
			     op->v_msvc_mask, len))
			continue;

		if (op->simple)
			return len + ofs;

		jo = je = 0;
		d_obj += ofs;
		d_exe += ofs;
		while (1)
		{
			for (; jo < len; jo++)
				if (op->v_masm_mask[jo] != 0xff)
					break;
			for (; je < len; je++)
				if (op->v_msvc_mask[je] != 0xff)
					break;

			if ((jo == len && je != len) || (jo != len && je == len)) {
				printf("invalid equiv_op #%td\n", op - equiv_ops);
				return -1;
			}
			if (jo == len)
				return len + ofs; // matched

			// var byte
			vo = d_obj[jo] & ~op->v_masm_mask[jo];
			ve = d_exe[je] & ~op->v_msvc_mask[je];
			if (op->cmp_rm && op->v_masm_mask[jo] == 0xc0) {
				vo2 = vo >> 3;
				vo &= 7;
				ve2 = ve & 7;
				ve >>= 3;
				if (vo != ve || vo2 != ve2)
					return -1;
			}
			else {
				if (vo != ve)
					return -1;
			}

			jo++;
			je++;
		}
	}

	return -1;
}

static void fill_int3(unsigned char *d, int len)
{
	while (len-- > 0) {
		if (d[0] == 0xcc && d[1] == 0xcc)
			break;
		*d++ = 0xcc;
	}
}

int main(int argc, char *argv[])
{
	unsigned int base = 0, addr, end, sym, *t;
	struct my_sect_info s_text_obj, s_text_exe;
	struct my_symtab *raw_syms_obj = NULL;
	struct my_symtab *syms_obj = NULL;
	long sym_cnt_obj, raw_sym_cnt_obj;
	FILE *f_obj, *f_exe;
	SCNHDR tmphdr;
	long sztext_cmn;
	int do_cmp = 1;
	int retval = 1;
	int bad = 0;
	int left;
	int arg;
	int ret;
	int i;

	for (arg = 1; arg < argc; arg++) {
		if (!strcmp(argv[arg], "-n"))
			do_cmp = 0;
		else
			break;
	}

	if (argc != arg + 2) {
		printf("usage:\n%s [-n] <a_obj> <exe>\n", argv[0]);
		return 1;
	}

	f_obj = fopen(argv[arg++], "r+b");
	if (f_obj == NULL) {
		fprintf(stderr, "%s: ", argv[1]);
		perror("");
		return 1;
	}

	f_exe = fopen(argv[arg++], "r");
	if (f_exe == NULL) {
		fprintf(stderr, "%s: ", argv[2]);
		perror("");
		return 1;
	}

	parse_headers(f_obj, NULL, &s_text_obj, &syms_obj, &sym_cnt_obj,
		      &raw_syms_obj, &raw_sym_cnt_obj);
	parse_headers(f_exe, &base, &s_text_exe, NULL, NULL, NULL, NULL);

	sztext_cmn = s_text_obj.size;
	if (sztext_cmn > s_text_exe.size)
		sztext_cmn = s_text_exe.size;

	if (sztext_cmn == 0) {
		printf("bad .text size(s): %ld, %ld\n",
			s_text_obj.size, s_text_exe.size);
		return 1;
	}

	for (i = 0; i < s_text_obj.reloc_cnt; i++)
	{
		unsigned int a = s_text_obj.relocs[i].r_vaddr;
		//printf("%04x %08x\n", s_text_obj.relocs[i].r_type, a);

		switch (s_text_obj.relocs[i].r_type) {
		case 0x06: // RELOC_ADDR32
		case 0x14: // RELOC_REL32
			// must preserve stored val,
			// so trash exe so that cmp passes
			memcpy(s_text_exe.data + a, s_text_obj.data + a, 4);
			break;
		default:
			printf("unknown reloc %x @%08x/%08x\n",
				s_text_obj.relocs[i].r_type, a, base + a);
			return 1;
		}
	}

	if (do_cmp)
	for (i = 0; i < sztext_cmn; i++)
	{
		if (s_text_obj.data[i] == s_text_exe.data[i]) {
			bad = 0;
			continue;
		}

		left = sztext_cmn - i;

		ret = try_align(s_text_obj.data + i, s_text_exe.data + i, left);
		if (ret > 0) {
			i += ret - 1;
			continue;
		}

		ret = check_equiv(s_text_obj.data + i, s_text_exe.data + i, left);
		if (ret >= 0) {
			i += ret - 1;
			continue;
		}

		printf("%x: %02x vs %02x\n", base + i,
			s_text_obj.data[i], s_text_exe.data[i]);
		if (bad)
			goto out;

		bad = 1;
	}

	// fill removed funcs with 'int3'
	for (i = 0; i < sym_cnt_obj; i++) {
		if (strncmp(syms_obj[i].name, "rm_", 3))
			continue;

		addr = syms_obj[i].addr;
		end = (i < sym_cnt_obj - 1)
			? syms_obj[i + 1].addr : s_text_obj.size;
		if (addr >= s_text_obj.size || end > s_text_obj.size) {
			printf("addr OOR: %x-%x '%s'\n", addr, end,
				syms_obj[i].name);
			goto out;
		}
		fill_int3(s_text_obj.data + addr, end - addr);
	}

	// remove relocs
	for (i = 0; i < s_text_obj.reloc_cnt; i++) {
		addr = s_text_obj.relocs[i].r_vaddr;
		sym = s_text_obj.relocs[i].r_symndx;
		if (addr > s_text_obj.size - 4) {
			printf("reloc addr OOR: %x\n", addr);
			goto out;
		}
		if (sym >= raw_sym_cnt_obj) {
			printf("reloc sym OOR: %d/%ld\n",
				sym, raw_sym_cnt_obj);
			goto out;
		}
#if 0
		printf("r %08x -> %08x %s\n", base + addr,
			raw_syms_obj[sym].addr,
			raw_syms_obj[sym].name);
#endif
		t = (unsigned int *)(s_text_obj.data + addr);
		if (t[0] == 0xcccccccc
		 || t[-1] == 0xcccccccc) { // jumptab of a func?
		 	t[0] = 0xcccccccc;
			memmove(&s_text_obj.relocs[i],
				&s_text_obj.relocs[i + 1],
				(s_text_obj.reloc_cnt - i - 1)
				 * sizeof(s_text_obj.relocs[0]));
			i--;
			s_text_obj.reloc_cnt--;
		}
#if 0
		// note: branches/calls already linked,
		// so only useful for dd refs
		// XXX: rm'd because of switch tables
		else if (raw_syms_obj[sym].is_text) {
			unsigned int addr2 = raw_syms_obj[sym].addr;
			if (s_text_obj.data[addr2] == 0xcc) {
				printf("warning: reloc %08x -> %08x "
					"points to rm'd target '%s'\n",
					base + addr, base + addr2,
					raw_syms_obj[sym].name);
			}
		}
#endif
	}

	// patch .text
	ret = fseek(f_obj, s_text_obj.sect_fofs, SEEK_SET);
	my_assert(ret, 0);
	ret = fwrite(s_text_obj.data, 1, s_text_obj.size, f_obj);
	my_assert(ret, s_text_obj.size);

	// patch relocs
	ret = fseek(f_obj, s_text_obj.reloc_fofs, SEEK_SET);
	my_assert(ret, 0);
	ret = fwrite(s_text_obj.relocs, sizeof(s_text_obj.relocs[0]),
		s_text_obj.reloc_cnt, f_obj);
	my_assert(ret, s_text_obj.reloc_cnt);

	ret = fseek(f_obj, s_text_obj.scnhdr_fofs, SEEK_SET);
	my_assert(ret, 0);
	ret = fread(&tmphdr, 1, sizeof(tmphdr), f_obj);
	my_assert(ret, sizeof(tmphdr));

	tmphdr.s_nreloc = s_text_obj.reloc_cnt;

	ret = fseek(f_obj, s_text_obj.scnhdr_fofs, SEEK_SET);
	my_assert(ret, 0);
	ret = fwrite(&tmphdr, 1, sizeof(tmphdr), f_obj);
	my_assert(ret, sizeof(tmphdr));

	fclose(f_obj);
	fclose(f_exe);

	retval = 0;
out:
	return retval;
}
