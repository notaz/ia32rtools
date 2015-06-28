; call a func with ebp reg-arg

_text           segment para public 'CODE' use32

call_test       proc near
                mov     ebp, 1
                jmp     ebpcall_func
call_test       endp

_text           ends

; vim:expandtab
