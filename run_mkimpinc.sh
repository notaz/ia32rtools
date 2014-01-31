#!/bin/sh
set -e

echo -n > $1

cat $2 | \
while read a; do
  a_no_at=`echo $a | awk -F@ '{printf $1}'`
  #echo "$a_no_at equ _$a" >> $1
  #echo "EXTRN _$a:PROC" >> $1
  echo "EXTRN $a:PROC" >> $1
done

if test -n "$3"; then
  echo "; '_' funcs" >> $1

  cat $3 | \
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

    echo "EXTRN $a:PROC" >> $1
  done
fi
