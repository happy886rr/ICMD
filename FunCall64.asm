;CALL 64 APL, MADE BY SLIMAY 2021.09.15

.CODE 
FunCall64 PROC
	;  ������ַ     ��������     ������Ŀ     ����ģʽ
	;intptr_t* hProc, intptr_t *arr, int len, bool needINT64

	;�ȱ��ݴ���Ĳ���ֵ
	mov	qword ptr [rsp +20h],  r9 
	mov	qword ptr [rsp +18h],  r8  
	mov	qword ptr [rsp +10h],  rdx 
	mov	qword ptr [rsp + 8h],  rcx 

	;�Ĵ���ԭʼֵ��ջ
	push		rdi
	push		rbx
	;ջָ�뱸��
	mov	rdi, rsp

	;�趨���ٴ���ջ�ռ�(����5��int64�ռ�, 16�ֽڶ���)
	sub	rsp, 28h

	;������������Ƿ񳬹�4��, (û���� 4��, ��ֱ����תFUN2���ٴ���)
	mov	eax, r8d
	cmp	eax, 5
	;С��5������ֱ����ת FUN2���ٴ���
	jb	FUN2

	;����ǳ���4�����������(����� ��������� βָ��� ��һָ��)
	lea	rbx, [rdx + r8 *8h]

	;������4�������� ʣ����� ��ջ
	LOOP1:
		;arr ǰ��
		sub	rbx, 8h

		;����������ջ
		mov	rax, qword ptr [rbx]  
		push	rax		

		;����������ѹ��
		cmp	rbx, rdx 
		jnz	LOOP1               

	;���Ʋ�����Ŀ, �Ա�֮��Ƚ�
	mov	eax, r8d

FUN2:
	;���ƴ�������ָ��
	mov rbx, qword ptr [rdi + 20h]

	;������޲�������
	cmp	eax, 0
	je	FUN1

	;�����1������
	mov	rcx,qword ptr [rbx + 0h]  
	cmp	eax, 1
	je FUN1

	;�����2������
	mov	rdx,qword ptr [rbx + 8h]
	cmp	eax, 2
	je FUN1

	;�����3������
	mov	r8, qword ptr [rbx + 10h] 
	cmp	eax, 3
	je FUN1

	;�����4������
	mov	r9, qword ptr [rbx + 18h]

FUN1:
	;����dll�еĺ���
	mov     rbx, qword ptr [rdi + 18h]
	call    rbx

	;��ȡ����ģʽ����
	mov     rbx, qword ptr [rdi + 30h]
	;�������ģʽΪ��, �������ָ��
	cmp     rbx, 1
	je      FUNINT

	;���Ƹ�������������
	movsd       mmword ptr [rsp+20h], xmm0 
	jmp      FUN0

FUNINT:
	;����������������
	mov         qword ptr  [rsp+20h], rax


FUN0:
	;������������ָ�� 
	mov         rax,  qword ptr [rsp+20h]  
	;�ָ�ջָ��
	mov	rsp, rdi
	;�Ĵ���ԭʼֵ��ջ
	pop	rbx
	pop	rdi  


	ret  

FunCall64 ENDP
END
