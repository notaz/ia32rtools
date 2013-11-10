#!/bin/sh -x

# sed -i -e '/.model flat/i\
# \t\t.xmm\r' StarCraft.asm

usyms="copy_start ___from_strstr_to_strchr unknown_libname_36 unknown_libname_41 unknown_libname_58"

f=/tmp/sedcmd_
echo -n "sed -i -e '/.model flat/i\\\t\t.xmm\r' -e '" > $f
for sym in $usyms; do
  echo -n "s/^\<$sym\>:\([^:]\)/$sym::\1/g;" >> $f
done

echo "\
s/^\(loc[r_].*[0-9A-F]:\)[^:]\(.*\;\)/\1:\t\2/g;\
s/dd[[:blank:]]rva/dd/;\
s/\<fldcw\>\t\[esp+4+var_4\]/fldcw\tword ptr \[esp\]/;\
s/\<large \(.*fs:\)/\1/;\
s/lea\t\(e.[px]\), \[\1+0\]/align 10h/;\
s/\[\(e..\)+\(e.p\)\]/\[\2+\1\]/;\
s/\(\<word_.*\), 0FFFFh/\1, word ptr 0FFFFh/;\
s/\(\<j[mn]\?[abceglopszp]e\?\>\)\tloc_/\1\tnear ptr loc_/;\
' StarCraft.asm" >> $f
. $f

# manual fixup:
# = 'end start' -> 'end'
# - 'lea     ecx, [ecx+0]' -> align
# - add 'near ptr' to some jumps
# - 'cmp     [ebp+edx+0], cl' -> 'cmp     [edx+ebp+0], cl'
# - 0FFFFh constant - masm treats a byte, sometimes prefix with 'word ptr'
