; sub_test() has no args
; need this to be able to call fastcall funcs anywhere, as fastcall may
; sit in some fastcall table even when it doesn't use reg args

_text           segment para public 'CODE' use32

; sctattr: clear_regmask=0c
sub_test        proc near
                xor     ebx, ebx
                push    1
                jmp     fastcall_func
sub_test        endp

_text           ends

; vim:expandtab
