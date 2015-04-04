
_text           segment para public 'CODE' use32

sub_test        proc near

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
                fld1
                fdivrp  [ebp+var_18]
                fld     st(1)
                fstp    [ebp+var_18]
                fst     [ebp+var_20]
                call    __ftol
                leave
                retn
sub_test        endp


_text           ends

; vim:expandtab
