static int my_isblank(char c)
{
	return c == '\t' || c == ' ' || c == '\r' || c == '\n';
}

static int my_issep(char c)
{
	return c == '(' || c == ')' || c == '[' || c == ']'
	    || c == '<' || c == '>' || c == ',' || c == ';'
	    || c == '+' || c == '-' || c == '*' || c == '/';
}

static char *sskip(char *s)
{
	while (my_isblank(*s))
		s++;

	return s;
}

static char *next_word(char *w, size_t wsize, char *s)
{
	size_t i;

	s = sskip(s);

	for (i = 0; i < wsize - 1; i++) {
		if (s[i] == 0 || my_isblank(s[i]))
			break;
		w[i] = s[i];
	}
	w[i] = 0;

	if (s[i] != 0 && !my_isblank(s[i]))
		printf("warning: '%s' truncated\n", w);

	return s + i;
}

static inline char *next_idt(char *w, size_t wsize, char *s)
{
	size_t i;

	s = sskip(s);

	for (i = 0; i < wsize - 1; i++) {
		if (s[i] == 0 || my_isblank(s[i]) || my_issep(s[i]))
			break;
		w[i] = s[i];
	}
	w[i] = 0;

	if (s[i] != 0 && !my_isblank(s[i]) && !my_issep(s[i]))
		printf("warning: '%s' truncated\n", w);

	return s + i;
}
