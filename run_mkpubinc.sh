#!/bin/sh
set -e

echo -n > $1

cat $2 | fromdos | sed -e \
'1,/^_rdata.*segment/d;/^_data.*\<ends\>/q;/^[[:blank:];]/d;/^;/d;/^_r\?data\>/d;' | awk '{print $1}' | \
while read a; do
  test -z "$a" && continue
  case $a in
  __IMPORT_DESCRIPTOR*)
    continue
    ;;
  _data)
    continue
    ;;
  *)
    ;;
  esac

  echo "_$a equ $a" >> $1
  echo "PUBLIC _$a" >> $1
done

if test -n "$3"; then
  echo "; funcs called from C" >> $1

  cat $3 | \
  while read a; do
#    echo "_$a equ $a" >> $1
#    echo "PUBLIC _$a" >> $1
    a=`echo $a | awk -F@ '{print $1}'`
    echo "PUBLIC $a" >> $1
  done
fi
