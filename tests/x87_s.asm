
_text           segment para public 'CODE' use32

sub_test        proc near

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 4
                mov     [ebp+var_4], 4
                fild    [ebp+var_4]
                fld     [ebp+var_4]
                fild    [ebp+var_4]
                fld1
                fild    [ebp+var_4]
                fldz
                fldln2
                fild    [ebp+var_4]
                faddp   st, st(7)
                fdivp   st(5), st
                fyl2x
                fsubp   st(2), st
                fsubrp  st, st
                fxch    st(6)
                fchs
                fpatan
                fist    [ebp+var_4]
                fstp    [ebp+var_4]
                mov     esp, ebp
                pop     ebp
                retn
sub_test        endp

_text           ends

; vim:expandtab
