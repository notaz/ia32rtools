; special case of callee sharing the stack frame

_text           segment para public 'CODE' use32

sub_test        proc near

var_8           = dword ptr -8

                push    ebp
                mov     ebp, esp
                sub     esp, 8
                mov     [ebp+var_8], 1
                call    ebpcall_func
                and     eax, 0
                leave
                retn
sub_test        endp

_text           ends

; vim:expandtab
