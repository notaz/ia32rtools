#!/bin/sh

if [ -z "$1" ]; then
  echo "usage:"
  echo "$0 <basename>"
  exit 1
fi

cp -v reg_call1.asm $1.asm
touch $1.expect.c
touch $1.seed.h
