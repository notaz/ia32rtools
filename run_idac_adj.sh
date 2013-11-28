#!/bin/sh -x
set -e

f=/tmp/sedcmd_
echo -n "sed -i '\
s:__cdecl: /*__cdecl*/:;\
s:__stdcall: /*__stdcall*/:;\
s:__usercall: /*__usercall*/:;\
s:__userpurge: /*__userpurge*/:;\
s:__thiscall: /*__thiscall*/:;\
s:__fastcall: /*__fastcall*/:;\
s:\(<[^<> ]*>\):/*\1*/:g;\
' $1" > $f
. $f

