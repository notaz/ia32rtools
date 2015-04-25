
_text           segment para public 'CODE' use32

sub_test        proc near

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 4
                mov     [ebp+var_4], 4
                fild    [ebp+var_4]
                fild    [ebp+var_4]
                fsqrt
                fpatan
                call    __ftol
                mov     esp, ebp
                pop     ebp
                retn
sub_test        endp

_text           ends

; vim:expandtab
