#!/bin/sh

grep 'extrn ' StarCraft.asm | awk '{print $2}' | awk -F: '{print $1}' > implist

echo ".data" > $1
echo ".align 4" >> $1

cat implist | while read i; do
  rm -f tmpsym
  case $i in
  __imp_*)
    si=`echo $i | cut -c 7-`
    ;;
  *)
    si=$i
    ;;
  esac

  grep "\<_$si\>" /usr/i586-mingw32msvc/lib/lib* *.lib | awk '{print $3}' | \
    while read f; do
      sym=`i586-mingw32msvc-nm $f | grep "\<_$si\>" | grep ' T ' | awk '{print $3}'`
      if test -n "$sym"; then
        echo $sym > tmpsym
        break
      fi
    done
  sym=`cat tmpsym`
  if test -z "$sym"; then
    echo "no file/sym for $i, lf $f"
    exit 1
  fi

  echo ".globl $i" >> $1
  echo "$i:" >> $1
  echo "  .long $sym" >> $1
  echo >> $1
done
