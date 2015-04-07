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
s/^\([ +-]\?loc[r_].*[0-9A-F]:\)[^:]\(.*\;\)/\1:\t\2/g;\
s/dd[[:blank:]]rva/dd/;\
s/\<fldcw\>\t\[esp+4+var_4\]/fldcw\tword ptr \[esp\]/;\
s/\<large \(.*fs:\)/\1/;\
s/lea\t\(e.[px]\), \[\1+0\]/align 10h/;\
s/\[\(e..\)+\(e.p\)\]/\[\2+\1\]/;\
s/\<lea\t\(e..\), \[\(e.p\)+\(e.x\)+/lea\t\1, \[\3+\2+/;\
s/\[\(e.p\)+\(e.i\)+/\[\2+\1+/;\
s/\<pushf\>/pushfd/;\
s/\<popf\>/popfd/;\
s/\(\<j[mn]\?[abceglopszp]e\?\>\)\tloc_/\1\tnear ptr loc_/;\
s/\<jmp\tsub_/jmp\tnear ptr sub_/;\
' $1" >> $f
. $f
