
_text           segment para public 'CODE' use32

sub_test        proc near
                push    ebp
                mov     ebp, esp
                call    fastcall_func
                and     eax, 0
                pop     ebp
                retn
sub_test        endp

_text           ends

; vim:expandtab
