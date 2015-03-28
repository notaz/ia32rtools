
_text           segment para public 'CODE' use32

sub_test        proc near
                push    ebp
                mov     ebp, esp
                call    fastcall_func
                inc     ecx
                pop     ebp
                retn
sub_test        endp

_text           ends

; vim:expandtab
