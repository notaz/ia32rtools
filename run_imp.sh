#!/bin/sh

# warning: i686-w64-mingw32- on Ubuntu 14.04
# contains broken InterlockedDecrement
test -n "$mingwb" || mingwb=i686-w64-mingw32

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

  grep -e "\<_\?_$si\>" -e "@$si\>" /usr/$mingwb/lib/lib* "$@" | awk '{print $3}' | \
    while read f; do
      sym=`${mingwb}-nm $f | grep -e "\<_\?_$si\>" -e " @$si\>" | grep ' T ' | awk '{print $3}'`
      if test -n "$sym"; then
        echo $sym > $tmpsym
        break
      fi
    done
  sym=`cat $tmpsym`
  if test -z "$sym"; then
    # could be a data import
    if test -n "$data_symf" && grep -q "$si" $data_symf; then
      continue
    else
      echo "$target_s: no file/sym for $i"
      rm $target_s
      exit 1
    fi
  fi

  echo ".globl $i" >> $target_s
  echo "$i:" >> $target_s
  echo "  .long $sym" >> $target_s
  echo >> $target_s
done
