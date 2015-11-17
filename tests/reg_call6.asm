
_text           segment para public 'CODE' use32

sub_test        proc near
                push    ecx
                shl     ecx, 9
                push    edx
                and     edx, 7Fh
                add     ecx, 1
                call    sub_test2
                retn
sub_test        endp

_text           ends

; vim:expandtab
