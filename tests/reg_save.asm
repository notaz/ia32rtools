
_text           segment para public 'CODE' use32

sub_test        proc near
                push    ebp
                mov     ebp, esp
                push    ebx
                mov     ebx, 1
                push    ebx
                mov     ebx, 2
                pop     ebx
                or      eax, 0FFFFFFFFh
                pop     ebx
                pop     ebp
                retn
sub_test        endp

_text           ends

; vim:expandtab
