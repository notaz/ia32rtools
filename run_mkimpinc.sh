#!/bin/sh
set -e

echo -n > $3

cat $1 | \
while read a; do
  a_no_at=`echo $a | awk -F@ '{printf $1}'`
  echo "$a_no_at equ _$a" >> $3
  echo "EXTRN _$a:PROC" >> $3
done

echo "; '_' funcs" >> $3

cat $2 | \
while read a; do
  case $a in
  \#*)
    continue
    ;;
  \;*)
    continue
    ;;
  "")
    continue
    ;;
  *)
    ;;
  esac

  echo "EXTRN $a:PROC" >> $3
done
