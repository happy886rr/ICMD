;CALL 64 APL, MADE BY SLIMAY 2021.09.15

.CODE 
FunCall64 PROC
	;  函数地址     传参数组     传参数目     传参模式
	;intptr_t* hProc, intptr_t *arr, int len, bool needINT64

	;先备份传入的参数值
	mov	qword ptr [rsp +20h],  r9 
	mov	qword ptr [rsp +18h],  r8  
	mov	qword ptr [rsp +10h],  rdx 
	mov	qword ptr [rsp + 8h],  rcx 

	;寄存器原始值入栈
	push		rdi
	push		rbx
	;栈指针备份
	mov	rdi, rsp

	;设定快速传参栈空间(下移5个int64空间, 16字节对齐)
	sub	rsp, 28h

	;计算参数个数是否超过4个, (没超过 4个, 则直接跳转FUN2快速传参)
	mov	eax, r8d
	cmp	eax, 5
	;小于5个参数直接跳转 FUN2快速传参
	jb	FUN2

	;如果是超过4个参数的情况(计算出 传参数组的 尾指针的 后一指针)
	lea	rbx, [rdx + r8 *8h]

	;将超过4个参数的 剩余参数 入栈
	LOOP1:
		;arr 前移
		sub	rbx, 8h

		;参数倒序入栈
		mov	rax, qword ptr [rbx]  
		push	rax		

		;不相等则继续压参
		cmp	rbx, rdx 
		jnz	LOOP1               

	;复制参数数目, 以便之后比较
	mov	eax, r8d

FUN2:
	;复制传参数组指针
	mov rbx, qword ptr [rdi + 20h]

	;如果是无参数函数
	cmp	eax, 0
	je	FUN1

	;如果是1个参数
	mov	rcx,qword ptr [rbx + 0h]  
	cmp	eax, 1
	je FUN1

	;如果是2个参数
	mov	rdx,qword ptr [rbx + 8h]
	cmp	eax, 2
	je FUN1

	;如果是3个参数
	mov	r8, qword ptr [rbx + 10h] 
	cmp	eax, 3
	je FUN1

	;如果是4个参数
	mov	r9, qword ptr [rbx + 18h]

FUN1:
	;调用dll中的函数
	mov     rbx, qword ptr [rdi + 18h]
	call    rbx

	;获取返回模式参数
	mov     rbx, qword ptr [rdi + 30h]
	;如果返回模式为真, 输出整型指针
	cmp     rbx, 1
	je      FUNINT

	;复制浮点数的运算结果
	movsd       mmword ptr [rsp+20h], xmm0 
	jmp      FUN0

FUNINT:
	;复制整数的运算结果
	mov         qword ptr  [rsp+20h], rax


FUN0:
	;返回运算结果的指针 
	mov         rax,  qword ptr [rsp+20h]  
	;恢复栈指针
	mov	rsp, rdi
	;寄存器原始值出栈
	pop	rbx
	pop	rdi  


	ret  

FunCall64 ENDP
END
