#!/bin/sh

outf=$3

grep '@' $1 | awk '{print $1}' > ${outf}_explist

echo ".text" > $outf
echo ".align 4" >> $outf

cat ${outf}_explist | while read i; do
  sym=`echo $i | awk -F@ '{print $1}'`
  if grep -q "$sym" $2; then
    continue
  fi

  echo ".globl _$i" >> $outf
  echo "_$i:" >> $outf
  echo "  jmp $sym" >> $outf
  echo >> $outf
done
