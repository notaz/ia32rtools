
_text           segment para public 'CODE' use32

sub_test        proc near
                push    ebp
                mov     ebp, esp
                push    esi
                mov     esi, ptr_struct1
                push    1
                call    dword ptr [esi]
                mov     eax, [esi+4]
                push    2
                call    dword ptr [eax+4]
                pop     esi
                pop     ebp
                retn
sub_test        endp

_text           ends

_rdata          segment para public 'DATA' use32
ptr_struct1     dd 0
_rdata          ends

; vim:expandtab
