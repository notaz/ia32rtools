#!/bin/sh
set -e

echo -n > $3

cat $1 | fromdos | sed -e \
'1,/^_rdata.*segment/d;/^_data_last/q;/^[[:blank:];]/d;/^;/d;/^_r\?data\>/d;' | awk '{print $1}' | \
while read a; do
  test -z "$a" && continue
  case $a in
  __IMPORT_DESCRIPTOR*)
    continue
    ;;
  *)
    ;;
  esac

  echo "_$a equ $a" >> $3
  echo "PUBLIC _$a" >> $3
done

echo "; funcs called from C" >> $3

cat $2 | \
while read a; do
#  echo "_$a equ $a" >> $3
#  echo "PUBLIC _$a" >> $3
  a=`echo $a | awk -F@ '{print $1}'`
  echo "PUBLIC $a" >> $3
done
