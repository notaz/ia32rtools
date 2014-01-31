#!/bin/sh

grep 'extrn ' $1 | awk '{print $2}' | awk -F: '{print $1}' > $2_implist
extra_libs=`ls *.lib 2> /dev/null`

echo ".data" > $2
echo ".align 4" >> $2

cat $2_implist | while read i; do
  rm -f $2_tmpsym
  case $i in
  __imp_*)
    si=`echo $i | cut -c 7-`
    ;;
  *)
    si=$i
    ;;
  esac

  grep "\<_$si\>" /usr/i586-mingw32msvc/lib/lib* $extra_libs | awk '{print $3}' | \
    while read f; do
      sym=`i586-mingw32msvc-nm $f | grep "\<_$si\>" | grep ' T ' | awk '{print $3}'`
      if test -n "$sym"; then
        echo $sym > $2_tmpsym
        break
      fi
    done
  sym=`cat $2_tmpsym`
  if test -z "$sym"; then
    echo "no file/sym for $i, lf $f"
    exit 1
  fi

  echo ".globl $i" >> $2
  echo "$i:" >> $2
  echo "  .long $sym" >> $2
  echo >> $2
done
