#!/bin/sh
set -e

public_inc=$1
asm=$2
c_list=$3

echo -n > $public_inc

cat $asm | fromdos | sed -e \
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

  echo "_$a equ $a" >> $public_inc
  echo "PUBLIC _$a" >> $public_inc
done

if test -n "$c_list"; then
  # make a list of functions in asm
  grep '\<endp\>' $asm | awk '{print $1}' | grep -v '\<rm_' \
    > ${asm}_funcs || true

  echo "; funcs called from C" >> $public_inc

  cat $c_list | \
  while read a; do
    name=`echo $a | awk -F@ '{print $1}'`
    n=`grep "\<$name\>" ${asm}_funcs` || \
    n=`grep "\<_$name\>" ${asm}_funcs` || true
    if test -z "$n"; then
      echo "\"$name\" is expected to be in asm, but was not found"
      rm $public_inc
      exit 1
    fi
    echo "PUBLIC $n" >> $public_inc
  done
fi
