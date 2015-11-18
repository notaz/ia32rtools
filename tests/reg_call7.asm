; this is a huge mess, but similar horrors
; have been seen coming from msvc...

_text           segment para public 'CODE' use32

sub_test        proc near
                push    ebx

                add     ecx, 1
                push    ecx
                mov     ebx, ecx

                push    ebx
                add     ebx, 1
                jz      l4
                jns     l2
                call    sub_test1

                push    ebx
                add     ebx, 1
l2:
                call    sub_test2

                push    ebx
                add     ebx, 1
back:
                push    ebx
                add     ebx, 1
                test    ebx, ebx
                jz      l4
                push    ebx
                add     ebx, 1
                test    ebx, ebx
                ja      l5
                call    sub_test3

                push    ebx
                add     ebx, 1
                test    ebx, ebx
                jz      back

                push    ebx
                add     ebx, 1
l4:
                push    ebx
                add     ebx, 1
                call    sub_test4

                push    ebx
                add     ebx, 1
                push    ebx
                add     ebx, 1
l5:
                push    ebx
                add     ebx, 1
                push    ebx
                add     ebx, 1
                push    ebx
                add     ebx, 1
                call    sub_test6
                call    sub_test5

                mov     eax, ebx
                pop     ebx
                retn
sub_test        endp

_text           ends

; vim:expandtab
