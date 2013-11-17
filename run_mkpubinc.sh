#!/bin/sh

echo -n > public.inc

cat StarCraft.asm | fromdos | sed -e \
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

  echo "PUBLIC $a" >> public.inc
done
