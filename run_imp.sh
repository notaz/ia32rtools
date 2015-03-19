#!/bin/sh

mingwb=i686-w64-mingw32

target_s=$1
src_asm=$2
implist=${target_s}_implist
tmpsym=${target_s}_tmpsym
shift 2

grep 'extrn ' $src_asm | awk '{print $2}' | \
  awk -F: '{print $1}' > $implist

echo ".data" > $target_s
echo ".align 4" >> $target_s

cat $implist | while read i; do
  rm -f $tmpsym
  case $i in
  __imp_*)
    si=`echo $i | cut -c 7-`
    ;;
  *)
    si=$i
    ;;
  esac

  grep "\<_\?_$si\>" /usr/$mingwb/lib/lib* "$@" | awk '{print $3}' | \
    while read f; do
      sym=`${mingwb}-nm $f | grep "\<_\?_$si\>" | grep ' T ' | awk '{print $3}'`
      if test -n "$sym"; then
        echo $sym > $tmpsym
        break
      fi
    done
  sym=`cat $tmpsym`
  if test -z "$sym"; then
    echo "no file/sym for $i, lf $f"
    exit 1
  fi

  echo ".globl $i" >> $target_s
  echo "$i:" >> $target_s
  echo "  .long $sym" >> $target_s
  echo >> $target_s
done
