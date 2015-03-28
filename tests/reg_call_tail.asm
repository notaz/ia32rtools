
_text           segment para public 'CODE' use32

sub_test        proc near
                mov     ebx, 1
                jmp     fastcall_func
sub_test        endp

_text           ends

; vim:expandtab
