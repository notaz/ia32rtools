; test random ops

_text           segment para public 'CODE' use32

sub_test        proc near
                push    ebp
                push    ebx
                push    esi
                push    edi
                mov     ebx, 10000h
                mov     esi, 20000h
                mov     edi, 30000h
                mov     ecx, 10
loop:
                lodsb
                xlat
                stosb
                lodsw
                neg     ax
                stosw
                lodsd
                stosd
                movsb
                cmpsw
                scasb
                loop    loop

                std
                stosb
                stosw
                stosd
                cld

                cdq
                bsf     eax, ecx

                push    1
                pop     eax
                pop     edi
                pop     esi
                pop     ebx
                pop     ebp
                retn
sub_test        endp

_text           ends

; vim:expandtab
