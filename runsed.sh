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
' StarCraft.asm" >> $f
. $f

