#!/bin/sh

grep '@' $1 | awk '{print $1}' > $2_explist

echo ".text" > $2
echo ".align 4" >> $2

cat $2_explist | while read i; do
  sym=`echo $i | awk -F@ '{print $1}'`

  echo ".globl _$i" >> $2
  echo "_$i:" >> $2
  echo "  jmp $sym" >> $2
  echo >> $2
done
