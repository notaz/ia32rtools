#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "my_assert.h"
#include "my_str.h"

struct sl_item {
	char *name;
	unsigned int callsites:1;
	unsigned int found:1;
};

static int cmp_sym(const void *p1_, const void *p2_)
{
	const struct sl_item *p1 = p1_, *p2 = p2_;
	const char *s1 = p1->name, *s2 = p2->name;
	int i;

	for (i = 0; ; i++) {
		if ((s1[i] | s2[i]) == 0)
			break;

		if (s1[i] == s2[i])
			continue;

		if (s1[i] ==  0  && s2[i] == '@')
			break;
		if (s1[i] == '@' && s2[i] ==  0)
			break;

		return s1[i] - s2[i];
	}

	return 0;
}

static int cmp_sym_sort(const void *p1_, const void *p2_)
{
	const struct sl_item *p1 = p1_, *p2 = p2_;
	const char *s1 = p1->name, *s2 = p2->name;
	int ret;
	
	ret = cmp_sym(p1_, p2_);
	if (ret == 0) {
		printf("%s: dupe sym: '%s' '%s'\n", __func__, s1, s2);
		exit(1);
	}
	return ret;
}

void read_list(struct sl_item **sl_in, int *cnt, int *alloc,
	FILE *f, int callsites)
{
	struct sl_item *sl = *sl_in;
	int c = *cnt;
	char line[256];
	char word[256];

	while (fgets(line, sizeof(line), f) != NULL) {
		next_word(word, sizeof(word), line);
		if (word[0] == 0 || word[0] == ';' || word[0] == '#')
			continue;

		sl[c].name = strdup(word);
		sl[c].callsites = callsites;
		sl[c].found = 0;
		c++;

		if (c >= *alloc) {
			*alloc *= 2;
			sl = realloc(sl, *alloc * sizeof(sl[0]));
			my_assert_not(sl, NULL);
			memset(sl + c, 0, (*alloc - c) * sizeof(sl[0]));
		}
	}

	*sl_in = sl;
	*cnt = c;
}

const char *sym_use(const struct sl_item *sym)
{
	static char buf[256+3];
	int ret;

	ret = snprintf(buf, sizeof(buf), "rm_%s", sym->name);
	if (ret >= sizeof(buf)) {
		printf("truncation detected: '%s'\n", buf);
		exit(1);
	}

	return buf;
}

#define IS(w, y) !strcasecmp(w, y)
#define IS_OR2(w, x, y) (IS(w, x) || IS(w, y))
#define IS_OR3(w, x, y, z) (IS(w, x) || IS(w, y) || IS(w, z))

int main(int argc, char *argv[])
{
	struct sl_item *symlist, *sym, ssym = { NULL, };
	int patch_callsites = 0;
	FILE *fout, *fin, *f;
	int symlist_alloc;
	int symlist_cnt;
	char line[256];
	char word[256];
	char word2[256];
	char word3[256];
	char word4[256];
	char word5[256];
	char word6[256];
	char *p;
	int i;

	if (argc < 4) {
		// -c - patch callsites
		printf("usage:\n%s <asmf_out> <asmf_in> [[-c] <listf>]*>\n",
			argv[0]);
		return 1;
	}

	symlist_alloc = 16;
	symlist_cnt = 0;
	symlist = calloc(symlist_alloc, sizeof(symlist[0]));
	my_assert_not(symlist, NULL);

	for (i = 3; i < argc; i++) {
		if (strcmp(argv[i], "-c") == 0) {
			patch_callsites = 1;
			continue;
		}

		f = fopen(argv[i], "r");
		my_assert_not(f, NULL);
		read_list(&symlist, &symlist_cnt, &symlist_alloc,
			f, patch_callsites);
		fclose(f);

		patch_callsites = 0;
	}

	qsort(symlist, symlist_cnt, sizeof(symlist[0]), cmp_sym_sort);

#if 0
	printf("symlist:\n");
	for (i = 0; i < symlist_cnt; i++)
		printf("%d '%s'\n", symlist[i].callsites, symlist[i].name);
#endif

	fin = fopen(argv[2], "r");
	my_assert_not(fin, NULL);

	fout = fopen(argv[1], "w");
	my_assert_not(fout, NULL);

	while (fgets(line, sizeof(line), fin))
	{
		p = sskip(line);
		if (*p == 0 || *p == ';')
			goto pass;

		p = sskip(next_word(word, sizeof(word), p));
		if (*p == 0 || *p == ';')
			goto pass; // need at least 2 words

		p = next_word(word2, sizeof(word2), p);

		if (IS_OR2(word2, "proc", "endp")) {
			ssym.name = word;
			sym = bsearch(&ssym, symlist, symlist_cnt,
				sizeof(symlist[0]), cmp_sym);
			if (sym != NULL) {
				sym->found = 1;
				fprintf(fout, "rm_%s\t%s%s", word, word2, p);
				continue;
			}
		}

		if (IS_OR3(word, "call", "jmp", "public")) {
			ssym.name = word2;
			sym = bsearch(&ssym, symlist, symlist_cnt,
				sizeof(symlist[0]), cmp_sym);
			if (sym != NULL && sym->callsites) {
				fprintf(fout, "\t\t%s\t%s%s", word,
					sym_use(sym), p);
				continue;
			}
		}

		p = sskip(p);
		if (*p == 0 || *p == ';')
			goto pass; // need at least 3 words

		p = next_word(word3, sizeof(word3), p);

		// dd offset <sym>
		// push offset <sym>
		// jcc short <sym>
		if ( (IS_OR2(word, "dd", "push") && IS(word2, "offset"))
		  || (word[0] == 'j' && IS(word2, "short")) ) {
			ssym.name = word3;
			sym = bsearch(&ssym, symlist, symlist_cnt,
				sizeof(symlist[0]), cmp_sym);
			if (sym != NULL && sym->callsites) {
				fprintf(fout, "\t\t%s %s %s%s",
					word, word2, sym_use(sym), p);
				continue;
			}
		}

		p = sskip(p);
		if (*p == 0 || *p == ';')
			goto pass; // need at least 4 words

		p = next_word(word4, sizeof(word4), p);

		// <name> dd offset <sym>
		if (IS(word2, "dd") && IS(word3, "offset")) {
			ssym.name = word4;
			sym = bsearch(&ssym, symlist, symlist_cnt,
				sizeof(symlist[0]), cmp_sym);
			if (sym != NULL && sym->callsites) {
				fprintf(fout, "%s\tdd offset %s%s", word,
					sym_use(sym), p);
				continue;
			}
		}

		// mov <something>, offset <sym>
		// jcc <some> ptr <sym>
		if ( (IS(word, "mov") && IS(word3, "offset"))
		  || (word[0] == 'j' && IS(word3, "ptr")) ) {
			ssym.name = word4;
			sym = bsearch(&ssym, symlist, symlist_cnt,
				sizeof(symlist[0]), cmp_sym);
			if (sym != NULL && sym->callsites) {
				fprintf(fout, "\t\t%s\t%s %s %s%s",
					word, word2, word3,
					sym_use(sym), p);
				continue;
			}
		}

		p = sskip(p);
		if (*p == 0 || *p == ';')
			goto pass; // need at least 5 words

		p = next_word(word5, sizeof(word5), p);

		p = sskip(p);
		if (*p == 0 || *p == ';')
			goto pass; // need at least 6 words

		p = next_word(word6, sizeof(word6), p);

		// <op> dword ptr <something>, offset <sym>
		if ( IS(word2, "dword") && IS(word3, "ptr")
		  && IS(word5, "offset") ) {
			ssym.name = word6;
			sym = bsearch(&ssym, symlist, symlist_cnt,
				sizeof(symlist[0]), cmp_sym);
			if (sym != NULL && sym->callsites) {
				fprintf(fout, "\t\t%s\tdword ptr %s offset %s%s",
					word, word4, sym_use(sym), p);
				continue;
			}
		}

pass:
		fwrite(line, 1, strlen(line), fout);
	}

	for (i = 0; i < symlist_cnt; i++) {
		if (!symlist[i].found)
			printf("warning: sym '%s' not found\n", symlist[i].name);
	}

	fclose(fin);
	fclose(fout);

	return 0;
}
