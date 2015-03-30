
_text           segment para public 'CODE' use32

sub_test        proc near

var_200         = byte ptr -200h
arg_0           = dword ptr  8
arg_4           = byte ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 200h
                lea     eax, [ebp+arg_4]
                push    eax             ; va_list
                lea     eax, [ebp+var_200]
                push    [ebp+arg_0]     ; char *
                push    200h            ; size_t
                push    eax             ; char *
                call    __vsnprintf
                add     esp, 10h
                leave
                retn
sub_test        endp

_text           ends

; vim:expandtab
