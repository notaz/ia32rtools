struct struct1 {
	void (__stdcall *f0)(int a1);
	struct struct2 *s1;
};

struct struct2 {
	int d0;
	int (__stdcall *f1)(int a1);
};

extern struct struct1 *ptr_struct1;
