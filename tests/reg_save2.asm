
_text           segment para public 'CODE' use32

sub_test        proc near
                push    ebp
                cmp     ecx, 0
                je      loc1
                push    ebx
                xor     eax, eax
                jmp     end
loc1:
                push    ebx
                mov     eax, 1
end:
                pop     ebx
                pop     ebp
                retn
sub_test        endp

_text           ends

; vim:expandtab
