
_text           segment para public 'CODE' use32

sub_test        proc near

var_28          = qword ptr -28h
var_20          = dword ptr -20h
var_18          = qword ptr -18h
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 20h
                fild    [ebp+var_20]
                fidiv   [ebp+arg_0]
                fmul    [ebp+var_18]
                fild    [ebp+var_20]
                fdiv    st(1), st
                faddp   st(1), st
                fld     [ebp+var_18]
                sub     esp, 10h
                fstp    [esp+30h+var_28]
                fstp    qword ptr [esp+0]
                call    _pow
                add     esp, 10h
                fcom    [ebp+var_18]
                xor     eax, eax
                fnstsw  ax
                test    ah, 41h
                mov     eax, 0
                setz    al
                fld1
                fdivr   [ebp+var_18]
                fxch    st(1)
                fchs
                fsubrp  st, st
                fld     st
                fyl2x
                fld     st
                fistp   [ebp+var_20]
                fst     [ebp+var_18]
                call    __ftol
                leave
                retn
sub_test        endp


_text           ends

; vim:expandtab
