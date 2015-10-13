#!/bin/sh

# export decorated symbols using undecorated ones from .asm
# $1 - .def
# $2 - .in_c
outf=$3

grep '@' $1 | grep -v '\<DATA\>' | grep -v '=' | \
  awk '{print $1}' > ${outf}_explist

echo ".text" > $outf
echo ".align 4" >> $outf

cat ${outf}_explist | while read i; do
  s0=`echo $i | cut -c 1`
  if [ "$s0" = "@" ]; then
    sym=`echo $i | awk -F@ '{print $2}'`
    pre=""
  else
    sym=`echo $i | awk -F@ '{print $1}'`
    pre="_"
  fi
  if grep -q "$sym" $2; then
    continue
  fi

  echo ".globl $pre$i" >> $outf
  echo "$pre$i:" >> $outf
  echo "  jmp $sym" >> $outf
  echo >> $outf
done
