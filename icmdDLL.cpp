#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <process.h>

// ���� ���ͱ�ʶ��
enum 
{
	TYPE_CHAR = '\'',      // �ַ��� 
	TYPE_INT = 'I',        // ����
	TYPE_FLOAT = 'F',      // ������  
	TYPE_DOUBLE = 'D',     // �߾��ȸ��� 
	TYPE_STRING = 'A',     // ANSI�ִ� 
	TYPE_WSTRING = 'L'     // UNICODE�ִ� 
};

// ����г�
#define MAX_LINE_SIZE 1024
// ���� ��� ������Ŀ
#define MAX_ARGV_SIZE 64

// ���صĿ���
#define MAX_LOAD_SIZE 64
int    load_lib_size = 0;
WCHAR  load_lib_name[ MAX_LOAD_SIZE ][MAX_PATH];

// ����call������ hash
#define MAX_HASH_SIZE 16
int hash_pointer = 0;
WCHAR  hash_fun_name[MAX_HASH_SIZE][MAX_PATH];
void* hash_fun_addr[MAX_HASH_SIZE];

// DLL������
#define DLL_EXPORT __declspec(dllexport)

// FunCall ��ຯ��
#ifdef  _WIN64
extern "C"  intptr_t  FunCall64( void*, intptr_t*, int, int );
#define WTOI _wtoi64 
#else
extern "C"  _int64  FunCall32( void*, intptr_t*, int, int );
#define WTOI _wtoi 
#endif

#ifndef _UINTPTR_T_DEFINED

#ifdef  _WIN64
typedef unsigned __int64    uintptr_t;
typedef __int64             intptr_t;
#else
typedef  unsigned int       uintptr_t;
typedef _W64 int            intptr_t;
#endif

#define _UINTPTR_T_DEFINED
#endif

// ���� ����ָ��
typedef BOOL ( WINAPI *PFNSETENVIRONMENTVARIABLE )( LPCWSTR, LPCWSTR );
// ���� ���ݺ���ָ��
PFNSETENVIRONMENTVARIABLE BakSetEnvironmentVariableW = NULL;

// IAT HOOK����
void IATHook(uintptr_t orgFun,  uintptr_t newFun)
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_IMPORT_DESCRIPTOR  pImportDescriptor;

#ifdef  _WIN64
	PIMAGE_NT_HEADERS64      pNTHeaders;
	PIMAGE_OPTIONAL_HEADER64 pOptHeader;
	PIMAGE_THUNK_DATA64      pThunkData;
#else
	PIMAGE_NT_HEADERS      pNTHeaders;
	PIMAGE_OPTIONAL_HEADER pOptHeader;
	PIMAGE_THUNK_DATA      pThunkData;
#endif


	// ��ȡ��ǰģ����̾��
	HMODULE hmod = GetModuleHandle( NULL );
	pDosHeader = ( PIMAGE_DOS_HEADER )hmod;

#ifdef  _WIN64
	pNTHeaders = ( PIMAGE_NT_HEADERS64 )( ( BYTE * )hmod + pDosHeader->e_lfanew );
	pOptHeader = ( PIMAGE_OPTIONAL_HEADER64 ) & ( pNTHeaders->OptionalHeader );
#else
	pNTHeaders = ( PIMAGE_NT_HEADERS )( ( BYTE * )hmod + pDosHeader->e_lfanew );
	pOptHeader = ( PIMAGE_OPTIONAL_HEADER ) & ( pNTHeaders->OptionalHeader );
#endif

	pImportDescriptor = ( PIMAGE_IMPORT_DESCRIPTOR )( ( BYTE * )hmod + pOptHeader->DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress );

	while( pImportDescriptor->FirstThunk )
	{

#ifdef  _WIN64
		pThunkData = ( PIMAGE_THUNK_DATA64 )( ( BYTE * )hmod + pImportDescriptor->OriginalFirstThunk );
#else
		pThunkData = ( PIMAGE_THUNK_DATA )( ( BYTE * )hmod + pImportDescriptor->OriginalFirstThunk );
#endif

		int offset = 1;
		while( pThunkData->u1.Function )
		{
			uintptr_t* opAddr = ( uintptr_t * )( ( BYTE * )hmod + ( DWORD )pImportDescriptor->FirstThunk ) + ( offset - 1 );
			if( ( * opAddr ) == ( uintptr_t )orgFun )
			{
				DWORD flOldProtect;

				// ʹģ���ڴ�� ��д
				VirtualProtect( opAddr, sizeof( uintptr_t ), PAGE_EXECUTE_READWRITE, &flOldProtect );
				// д���µĺ�����ַ
				WriteProcessMemory( GetCurrentProcess(), opAddr,  &newFun, sizeof( uintptr_t ), NULL );
				// �ָ�ģ���ڴ� ԭ����
				VirtualProtect( opAddr, sizeof( uintptr_t ), flOldProtect, 0 );
			}

			offset ++;
			pThunkData ++;
		}

		pImportDescriptor ++;
	}
}

// ��ȡ����ϵͳ�汾�� ����ֵ
FLOAT GetNtVersionFloat()
{
	BOOL bRet = FALSE;
	HMODULE hModNtdll = NULL;
	DWORD dwMajorVer, dwMinorVer, dwBuildNumber;

	if( hModNtdll = LoadLibraryW( L"ntdll.dll" ) )
	{
		typedef void ( WINAPI * pfRTLGETNTVERSIONNUMBERS )( DWORD*, DWORD*, DWORD* );
		pfRTLGETNTVERSIONNUMBERS pfRtlGetNtVersionNumbers = NULL;
		pfRtlGetNtVersionNumbers = ( pfRTLGETNTVERSIONNUMBERS )::GetProcAddress( hModNtdll, "RtlGetNtVersionNumbers" );
		if( pfRtlGetNtVersionNumbers )
		{
			pfRtlGetNtVersionNumbers( &dwMajorVer, &dwMinorVer, &dwBuildNumber );
			dwBuildNumber &= 0x0ffff;

			FLOAT verfv = dwMajorVer + dwMinorVer / 10.0f;
			return verfv;
		}

		::FreeLibrary( hModNtdll );
		hModNtdll = NULL;
	}

	return 0.0f;
}

//ת��ANSI����, strΪ��������
CHAR* WCS2STR( WCHAR* wstr, CHAR str[] )
{
	int len   = WideCharToMultiByte( CP_ACP, 0, wstr, -1, NULL, 0, NULL, NULL );
	WideCharToMultiByte( CP_ACP, 0, wstr, -1, str, len, NULL, NULL );
	return str;
}

// ���� �������� ����ֵ
void SetValue( WCHAR *varName, _int64 inValue, BOOL needINT )
{
	WCHAR varValue[MAX_PATH / 4];

	// �жϴ�����ֵҪ��ӡ�ɵ�����
	if( needINT == TRUE )
	{
		swprintf( varValue, L"%lld", inValue );
	}
	else
	{
		swprintf( varValue, L"%.12G", *( ( double * )&inValue ) );
	}

	// ���и�ֵ
	BakSetEnvironmentVariableW( varName, varValue );
}

// ����Ҫ���õĺ���ԭ��
#pragma warning( push )
extern "C"
{
	// ���� ��ֵ
	int iset( wchar_t* isetVarName, const wchar_t * _Format, ... )
	{
		wchar_t isetBuff[ MAX_PATH * 2 ];

		va_list _Arglist;
		_crt_va_start( _Arglist, _Format );
		int _Ret = _vswprintf( isetBuff, _Format, _Arglist );
		_crt_va_end( _Arglist );

		BakSetEnvironmentVariableW( isetVarName, isetBuff );
		return _Ret;
	}
	// ��ַ��ֵ
	int ispr( wchar_t* _String, const wchar_t * _Format, ... )
	{
		va_list _Arglist;
		_crt_va_start( _Arglist, _Format );
		int _Ret = _vswprintf( _String, _Format, _Arglist );
		_crt_va_end( _Arglist );
		return _Ret;
	}

	// �������
	BOOL ifill( void* _inData, const wchar_t * _Format, ... )
	{
		va_list _Arglist;
		_crt_va_start( _Arglist, _Format );

		BYTE* pb = ( BYTE * )_inData;
		wchar_t* p = ( wchar_t * )_Format;
		while( *p )
		{
			//���� SET ��ֵ����
			switch( *p )
			{
			case L'*':
			case L'~':
				{
					if( *( p + 1 ) == L'S' )
					{
						wchar_t* tmpArg = ( wchar_t * ) _crt_va_arg( _Arglist, intptr_t );
						// +1 Ϊ�˰���ĩβ�Ľ����� L'\0'
						int tmpArgLen = wcslen( tmpArg ) + 1;

						memcpy( pb, tmpArg, tmpArgLen * sizeof( wchar_t ) );
						pb += tmpArgLen * sizeof( wchar_t );
					}
					else if( L'1' == *( p + 1 ) )
					{
						intptr_t tmpArg = _crt_va_arg( _Arglist, intptr_t );
						memcpy( pb, &tmpArg, 1 );
						pb += 1;
					}
					else if( L'2' == *( p + 1 ) )
					{
						intptr_t tmpArg = _crt_va_arg( _Arglist, intptr_t );
						memcpy( pb, &tmpArg, 2 );
						pb += 2;
					}
					else if( L'4' == *( p + 1 ) )
					{
						intptr_t tmpArg = _crt_va_arg( _Arglist, intptr_t );
						memcpy( pb, &tmpArg, 4 );
						pb += 4;
					}
					else if( L'8' == *( p + 1 ) )
					{
						intptr_t tmpArg = _crt_va_arg( _Arglist, intptr_t );
						memcpy( pb, &tmpArg, 8 );
						pb += 8;
					}
					else
					{
						return FALSE;
					}

				}
				break;

			case L'+':
				// ָ�����
				pb += _wtoi( p + 1 );
				break;

			case L'-':
				// ָ��ǰ��
				pb -= _wtoi( p + 1 );
				break;

			default:
				// �޷�ʶ��ı�ʶ��
				return FALSE;
			}

			p += 2;
		}

		_crt_va_end( _Arglist );
		return TRUE;
	}

	// �������
	BOOL iout( void* _inData, const wchar_t * _Format, ... )
	{
		va_list _Arglist;
		_crt_va_start( _Arglist, _Format );

		BYTE* pb = ( BYTE * )_inData;
		wchar_t* p = ( wchar_t * )_Format;
		while( *p )
		{
			//���� SET ��ֵ����
			switch( *p )
			{
			case L'*':
			{
				if( *( p + 1 ) == L'S' )
				{
					wchar_t* tmpArg = _crt_va_arg( _Arglist, wchar_t* );
					wchar_t* tmpStr = ( wchar_t* ) pb;

					// +1 Ϊ�˰���ĩβ�Ľ����� L'\0'
					int tmpStrLen = wcslen( tmpStr ) + 1;

					BakSetEnvironmentVariableW( tmpArg, tmpStr );
					pb += tmpStrLen * sizeof( wchar_t );
				}
				else if( L'1' == *( p + 1 ) )
				{
					wchar_t* tmpArg = _crt_va_arg( _Arglist, wchar_t* );
					CHAR tmpStr = *( ( CHAR * ) pb );
					SetValue( tmpArg, ( intptr_t )tmpStr, TRUE );
					pb += 1;
				}
				else if( L'2' == *( p + 1 ) )
				{
					wchar_t* tmpArg = _crt_va_arg( _Arglist, wchar_t* );
					SHORT tmpStr = *( ( SHORT * ) pb );
					SetValue( tmpArg, ( intptr_t )tmpStr, TRUE );
					pb += 2;
				}
				else if( L'4' == *( p + 1 ) )
				{
					wchar_t* tmpArg = _crt_va_arg( _Arglist, wchar_t* );
					int tmpStr = *( ( int * ) pb );
					SetValue( tmpArg, ( intptr_t )tmpStr, TRUE );
					pb += 4;
				}
				else if( L'8' == *( p + 1 ) )
				{
					wchar_t* tmpArg = _crt_va_arg( _Arglist, wchar_t* );
					intptr_t tmpStr = *( ( intptr_t * ) pb );
					SetValue( tmpArg, ( intptr_t )tmpStr, TRUE );
					pb += 8;
				}
				else
				{
					return FALSE;
				}

			}
			break;

			// ����˫���ȸ���
			case L'~':
			{
				int num = _wtoi( p + 1 );
				wchar_t* tmpArg = _crt_va_arg( _Arglist, wchar_t* );
				if( num == 4 )
				{
					double tmpVal = ( double )( *( ( float * )pb ) );
					intptr_t tmpValInt =  *( ( intptr_t * )( & tmpVal ) );
					SetValue( tmpArg, tmpValInt, FALSE );
					pb += 4;
				}
				else if( num == 8 )
				{
					double tmpVal = *( ( double * )pb );
					intptr_t tmpValInt =  *( ( intptr_t * )( & tmpVal ) );
					SetValue( tmpArg, tmpValInt, FALSE );
					pb += 8;
				}
				else
				{
					return FALSE;
				}
			}
			break;

			case L'+':
				// ָ�����
				pb += _wtoi( p + 1 );
				break;

			case L'-':
				// ָ��ǰ��
				pb -= _wtoi( p + 1 );
				break;

			default:
				// �޷�ʶ��ı�ʶ��
				return FALSE;
			}

			p += 2;
		}

		_crt_va_end( _Arglist );
		return TRUE;
	}

}
#pragma warning( pop )

// FunCall ��ຯ��
#ifdef  _WIN64
	/*
		;64λ��� ���ڵ�����asm�ļ��з��ɱ���, ��������
		;intptr_t  FunCall64( void* hProc, intptr_t* DLLParam, int DLLParamNum, int needINT )
		;CALL 64 APL, MADE BY SLIMAY 2021.09.24

		.CODE 
		FunCall64 PROC
			;  ������ַ     ��������     ������Ŀ     ����ģʽ
			;intptr_t* hProc, void* DLLParam, int DLLParamNum, int needINT

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
	*/
#else
_int64  FunCall32( void* hProc, intptr_t* DLLParam, int DLLParamNum, int needINT )
{
	union
	{
		_int64  retInt64;
		int     retInt[2];
	} RetInt;
	// ����ֵ��������
	RetInt.retInt64 = 0;

	// ESP��������, ʵ�ּ��ݵ���stdcall �� cdecl
	int bakESP = 0;

	// ʹ���������, ��Ч�ȶ�
    __asm
    {
		;����ջ֡
		mov bakESP,	esp

		;��ȡ����Ĳ���
        mov		ebx, dword ptr [DLLParam]
        mov		ecx, dword ptr [DLLParamNum]
        dec		ecx 
		;����� �������� ĩβָ��
		lea		ebx, [ebx + ecx *4h]


	CYC: 
		;���� ȡ������
		mov		eax, dword ptr [ebx]
		;���� ָ��ǰ��
		sub		ebx, 4
		;ѹջ
		push	eax 
		dec		ecx
		; ��Ϊ��ֵ�������ѭ��ѹջ
		jns		CYC                

		;���ú���, ִ��call����
        call dword ptr [hProc]

		;�������ģʽΪ��, �������ָ��
		mov		ecx, dword ptr [needINT]
		cmp     ecx, 1
		je      FUNINT
		;���ظ���ֵ
        fstp	RetInt.retInt64;
		jmp		FUNEND

	FUNINT:
        mov		RetInt.retInt[0], eax

	FUNEND:
		;��� _cdecl ���ͺ�����call,���ϼ����ú���Ҳ����FunCall32 ���� �����ջ
		;�ָ�ջ֡
		mov		esp,	bakESP
    }

	// ���ؽ��
	return (RetInt.retInt64);
}
#endif

// ��������
LPWSTR cmdLineArgvBuff[ MAX_LINE_SIZE ];
LPWSTR* CommandLineToArgvW2( LPWSTR CmdLine, int* _argc)
{
	LPWSTR* argv  = ( LPWSTR *)  cmdLineArgvBuff;
	LPWSTR  _argv = ( LPWSTR  )( cmdLineArgvBuff + MAX_ARGV_SIZE + 1 );
	ULONG   len;
	ULONG   argc;
	WCHAR   a;
	ULONG   i, j;

	BOOLEAN  in_QM;
	BOOLEAN  in_TEXT;
	BOOLEAN  in_SPACE;

	argc = 0;
 	argv[argc] = _argv;
	in_QM = FALSE;
	in_TEXT = FALSE;
	in_SPACE = TRUE;
	i = 0;
	j = 0;

	while( a = CmdLine[i] )
	{
		if( in_QM )
		{
			if( a == L'"' )
			{
				in_QM = FALSE;
			}
			else
			{
				_argv[j] = a;
				j ++;
			}
		}
		else
		{
			switch( a )
			{
			case L'"':
				in_QM = TRUE;
				in_TEXT = TRUE;
				if( in_SPACE )
				{
					argv[argc] = _argv + j;
					argc ++;
				}
				in_SPACE = FALSE;
				break;

			case L' ':
			case L'\t':
			case L'\n':
			case L'\r':
				if( in_TEXT )
				{
					_argv[j] = L'\0';
					j ++;
				}
				in_TEXT = FALSE;
				in_SPACE = TRUE;
				break;

			default:
				in_TEXT = TRUE;
				if( in_SPACE )
				{
					argv[argc] = _argv + j;
					argc ++;
				}
				_argv[j] = a;
				j ++;
				in_SPACE = FALSE;
				break;
			}

			// ���ֻ���� MAX_ARGV_SIZE �������з�
			if(argc >= MAX_ARGV_SIZE )
			{
				break;
			}

		}
		i ++;
	}
	_argv[j] = L'\0';
	argv[argc] = NULL;

	( *_argc ) = argc;
	return argv;
}

// ��������, ������WINAPI��, ����hook�ɹ�
BOOL  WINAPI  ICMDCore( WCHAR* varName, WCHAR* varContent )
{
	// ����call ģʽ Ĭ��ֵ
	BOOL callMODE = TRUE;
	BOOL needINT  = TRUE;
	BOOL isISET   = FALSE;
	BOOL isISETP  = FALSE;

	//���� SET ��ֵ����
	switch( *varName )
	{
	case L'*':
		//���س�������
		needINT = TRUE;
		varName ++;
		break;

	case L'~':
		//����˫������
		needINT = FALSE;
		varName ++;
		break;

	default:
		//���� SET��ֵ
		BakSetEnvironmentVariableW( varName, varContent );
		return FALSE;
	}

	// ȥ�� ��ֵ������ ��ǰ�ո�
	while( * varName == L' ' || * varName == L'\t' )
	{
		varName ++;
	}
	// ȥ�� ��ֵ������ �ĺ�ո�
	WCHAR* pTmpV = varName;
	while(* pTmpV )
	{
		if(  *pTmpV == L' ' || *pTmpV == L'\t' )
		{
			*pTmpV = 0;
			break;
		}
		pTmpV ++;
	}

	// ȥ�� ��ֵ�ı�   ��ǰ�ո�
	while( * varContent == L' ' || * varContent == L'\t' )
	{
		varContent ++;
	}

	// �⻯�����в���
	int DLLargc = 0;
	WCHAR** DLLargv = CommandLineToArgvW2( varContent, &DLLargc );

	// ��������, ���߲�������64��,ֱ�Ӱչ�
	if( DLLargc < 1 || DLLargc > MAX_ARGV_SIZE )
	{

		return FALSE;
	}

	// Ҫcall�ĺ���ָ��
	void* hProc = NULL;

	// ������Զ��������, �򲻽���call ����, ֱ��ָ���Զ�������
	if( wcsicmp( DLLargv[0], L"ILOAD" ) == 0 )
	{
		load_lib_size = 0;
		for( int i = 1; i < DLLargc; i++ )
		{
			// ��ȡ ��ִ�� ģ����
			HMODULE hmod = LoadLibraryW( DLLargv[i] + 1 );
			if( hmod != NULL )
			{
				wcscpy( load_lib_name[ load_lib_size ], DLLargv[i] + 1 );
				load_lib_size ++;
			}
		}

		return TRUE;
	}
	else if( wcsicmp( DLLargv[0], L"ISET" ) == 0 )
	{
		if( DLLargc == 1 )
		{
			return FALSE;
		}

		// �滻��Ŀ�꺯��
		hProc = ( void * )iset;
	}
	else if( wcsicmp( DLLargv[0], L"ISPR" ) == 0 )
	{
		if( DLLargc == 1 )
		{
			return FALSE;
		}

		// �滻��Ŀ�꺯��
		hProc = ( void * )ispr;
	}
	else if( wcsicmp( DLLargv[0], L"IOUT" ) == 0 )
	{
		if( DLLargc == 1 )
		{
			return FALSE;
		}

		// �滻��Ŀ�꺯��
		hProc = ( void * )iout;
	}
	else if( wcsicmp( DLLargv[0], L"IFILL" ) == 0 )
	{
		if( DLLargc == 1 )
		{
			return FALSE;
		}

		// �滻��Ŀ�꺯��
		hProc = ( void * )ifill;
	}


	// ģ����
	HMODULE hmodDLL = NULL;
	if( hProc == NULL )
	{
		// ����ʹ�ÿ���hash������ call ������ַ
		for( int i = 0; i < MAX_HASH_SIZE; i++ )
		{
			int hashFunIndex = ( hash_pointer - i ) + MAX_HASH_SIZE;
			hashFunIndex %= MAX_HASH_SIZE;
			// ����֤ �״��Ƿ�ƥ��
			if( *( hash_fun_name[hashFunIndex] ) == *( DLLargv[0] ) )
			{
				continue;
			}
			if( wcscmp( hash_fun_name[hashFunIndex], DLLargv[0] ) == 0 )
			{
				hProc = ( void* ) hash_fun_addr[hashFunIndex];
				break;
			}
		}
	}

	// ���û���ҵ�, ��ʹ��ѭ������ÿ������ģ��, ���Ҹú�������Ӧ�ĵ�ַ
	if( hProc == NULL )
	{
		for( int i = 0; i < load_lib_size; i++ )
		{
			// ��ȡ��ִ��ģ�� ���return TRUE;
			hmodDLL =  GetModuleHandleW( load_lib_name[i] );

			// WCSToSTR
			CHAR funName[MAX_PATH];
			WCS2STR( DLLargv[0], funName );

			// ��ȡҪ call �ĺ�����ַ
			hProc = ( void* ) GetProcAddress( hmodDLL, funName );

			if( hProc != NULL )
			{
				// �ҵ������hashȦ��ջ
				hash_pointer ++;
				hash_pointer %= MAX_HASH_SIZE;
				wcscpy( hash_fun_name[hash_pointer], DLLargv[0] );
				hash_fun_addr[hash_pointer] = ( void* )hProc;
				break;
			}
		}
	}

	// �����ַ��ȻΪ��, ����Һ���ʧ��, ֱ�ӱ���
	if( hProc == NULL )
	{
		fwprintf( stderr, L"[ERROR]Can not load function '%s'\n", DLLargv[0] );
		return FALSE;
	}


	// WCSToSTR  (���ö�������ʵ��ת�������ַ��� ,�����ͷ�)
	CHAR tmpBuff[MAX_PATH / 4][MAX_PATH * 4];
	int tmpBuffIndex = 0;

	// ����-���� ת����
	union
	{
		double  fDB;
		#ifdef  _WIN64
				intptr_t iDB;
		#else
				intptr_t iDB[2];
				float smallfDB[2];
		#endif
	} F2I;


	// ����ָ�� ����
	intptr_t DLLParam[ MAX_ARGV_SIZE ];
	int DLLParamNum = 0;

	// ���ַ������� ת��Ϊ ���ݸ����Ĳ���
	int k = 0;
	while( k < DLLargc - 1 )
	{
		switch( DLLargv[k + 1][0] )
		{
		// ����
		case TYPE_INT:
			DLLParam[DLLParamNum] = WTOI( DLLargv[k + 1] + 1 );
			break;

		// ����
		case TYPE_FLOAT:
			#ifdef  _WIN64
			#else
				{
					F2I.smallfDB[0] = (float) wcstod( DLLargv[k + 1] + 1, NULL );
					DLLParam[DLLParamNum] = F2I.iDB[0];
					break;
				}
			#endif

		case TYPE_DOUBLE:
			F2I.fDB = wcstod( DLLargv[k + 1] + 1, NULL );

			#ifdef  _WIN64
					DLLParam[DLLParamNum] = F2I.iDB;
			#else
					DLLParam[DLLParamNum] = F2I.iDB[0];
					DLLParamNum ++;
					DLLParam[DLLParamNum] = F2I.iDB[1];
			#endif
			break;

		// �ַ���
		case TYPE_CHAR:
			DLLParam[DLLParamNum] = ( intptr_t )( *( ( CHAR* )( DLLargv[k + 1] + 1 ) ) );
			break;

		// �ַ�����
		case TYPE_STRING:
			// WCS2STR
			DLLParam[DLLParamNum] = ( intptr_t ) WCS2STR( DLLargv[k + 1] + 1,  tmpBuff[ tmpBuffIndex ++] );
			break;

		// WCHAR �ַ�, �ַ�������
		case TYPE_WSTRING:
			// ���ַ���
			if( *( DLLargv[k + 1] + 1 ) == TYPE_CHAR )
			{
				DLLParam[DLLParamNum] = ( intptr_t )( *( ( WCHAR* )( DLLargv[k + 1] + 2 ) ) );
			}
			// �ַ�����
			else
			{
				DLLParam[DLLParamNum] = ( intptr_t )( DLLargv[k + 1] + 1 );
			}
			break;

		//û�б�ʶ���� int���� _INT64 ����,
		default:
			// �������С������double����
			if( wcschr( DLLargv[k + 1], L'.' ) != NULL )
			{
				F2I.fDB = wcstod( DLLargv[k + 1], NULL );
				#ifdef  _WIN64
						DLLParam[DLLParamNum] = F2I.iDB;
				#else
						DLLParam[DLLParamNum] = F2I.iDB[0];
						DLLParamNum ++;
						DLLParam[DLLParamNum] = F2I.iDB[1];
				#endif
			}
			else
			{
				intptr_t val = WTOI( DLLargv[k + 1] );
				if( val == 0 )
				{
					// ֻ�������ַ�Ϊ0��ʱ��ż��� 16���� ת��
					wchar_t *end;
					val = ( intptr_t ) wcstoul( DLLargv[k + 1], &end, 16 );
				}
				DLLParam[DLLParamNum] = val;
			}
			break;
		}

		DLLParamNum ++;
		k ++;
	}


	// ������������ѹջ���ڶ�������Ϊ ��������ĵ�ַ, ����������Ϊ ��������ĳ���
#ifdef  _WIN64
	_int64 varValue = FunCall64( hProc, DLLParam, DLLParamNum, needINT );
#else
	_int64 varValue = FunCall32( hProc, DLLParam, DLLParamNum, needINT );
#endif

	if( *varName == L'\0')
	{
		return FALSE;
	}

	// ִ�б�׼��ֵ
	SetValue( varName, varValue, needINT );

	//���ô���� ����ֵ
	SetValue( L"errorlevel", ( int )GetLastError(), TRUE );

	return TRUE;
}

// ��������ʼ
BOOL WINAPI DllMain( HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpvReserved )
{
	switch (ul_reason_for_call)
	{
	// ִ��HOOK����
	case DLL_PROCESS_ATTACH:
		{
			// ��ȡģ��·��
			WCHAR processPath[MAX_PATH];
			GetModuleFileNameW( hModule, processPath, MAX_PATH );
			// ���Լ������ڴ�����
			LoadLibraryW( processPath );

			// ϵͳ����Win7, ��HOOK "kernelBase.dll"
			LPCWSTR hookDllName = ( GetNtVersionFloat() > 6.1001f ) ? ( L"kernelbase.dll" ) : ( L"kernel32.dll" );
			// ��ȡ ���к��� SetEnvironmentVariableW ��ַ
			uintptr_t hookAddress = ( uintptr_t )GetProcAddress( LoadLibraryW( hookDllName ), "SetEnvironmentVariableW" );

			// ����ԭ������ַ
			BakSetEnvironmentVariableW = ( PFNSETENVIRONMENTVARIABLE )hookAddress;
			// �� SetEnvironmentVariableW IAT����Ϊ ��ת�� �Զ��庯��
			IATHook( (uintptr_t)hookAddress, (uintptr_t)ICMDCore );

			// Ĭ�ϼ���һЩ������
			ICMDCore( L"*", L"ILOAD  L\"USER32.DLL\" L\"KERNEL32.DLL\" L\"GDI32.DLL\" L\"GDIPLUS.DLL\" L\"MSVCRT.DLL\"" );
			DisableThreadLibraryCalls( hModule );
		}
		break;

	case DLL_PROCESS_DETACH:
		// ж�� HOOK����
		if(BakSetEnvironmentVariableW != NULL)
		{
			// �� SetEnvironmentVariableW �ָ���ԭ��ַ
			IATHook( (uintptr_t)ICMDCore, (uintptr_t)BakSetEnvironmentVariableW );
		}
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}

	return TRUE;
}
