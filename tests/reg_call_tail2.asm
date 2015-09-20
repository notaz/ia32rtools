
_text           segment para public 'CODE' use32

sub_test        proc near

arg_0           = dword ptr  4

                inc     [esp+arg_0]
                jz      return_
                jmp     another_func
return_:
                retn    4
sub_test        endp

_text           ends

; vim:expandtab
