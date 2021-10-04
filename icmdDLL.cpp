#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <process.h>

// 定义 类型标识符
enum 
{
	TYPE_CHAR = '\'',      // 字符型 
	TYPE_INT = 'I',        // 整型
	TYPE_FLOAT = 'F',      // 浮点型  
	TYPE_DOUBLE = 'D',     // 高精度浮点 
	TYPE_STRING = 'A',     // ANSI字串 
	TYPE_WSTRING = 'L'     // UNICODE字串 
};

// 最大行长
#define MAX_LINE_SIZE 1024
// 定义 最大 传参数目
#define MAX_ARGV_SIZE 64

// 加载的库名
#define MAX_LOAD_SIZE 64
int    load_lib_size = 0;
WCHAR  load_lib_name[ MAX_LOAD_SIZE ][MAX_PATH];

// 构造call函数的 hash
#define MAX_HASH_SIZE 16
int hash_pointer = 0;
WCHAR  hash_fun_name[MAX_HASH_SIZE][MAX_PATH];
void* hash_fun_addr[MAX_HASH_SIZE];

// DLL导出宏
#define DLL_EXPORT __declspec(dllexport)

// FunCall 汇编函数
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

// 定义 函数指针
typedef BOOL ( WINAPI *PFNSETENVIRONMENTVARIABLE )( LPCWSTR, LPCWSTR );
// 定义 备份函数指针
PFNSETENVIRONMENTVARIABLE BakSetEnvironmentVariableW = NULL;

// IAT HOOK函数
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


	// 获取当前模块进程句柄
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

				// 使模块内存可 读写
				VirtualProtect( opAddr, sizeof( uintptr_t ), PAGE_EXECUTE_READWRITE, &flOldProtect );
				// 写入新的函数地址
				WriteProcessMemory( GetCurrentProcess(), opAddr,  &newFun, sizeof( uintptr_t ), NULL );
				// 恢复模块内存 原属性
				VirtualProtect( opAddr, sizeof( uintptr_t ), flOldProtect, 0 );
			}

			offset ++;
			pThunkData ++;
		}

		pImportDescriptor ++;
	}
}

// 获取操作系统版本号 浮点值
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

//转码ANSI函数, str为容器数组
CHAR* WCS2STR( WCHAR* wstr, CHAR str[] )
{
	int len   = WideCharToMultiByte( CP_ACP, 0, wstr, -1, NULL, 0, NULL, NULL );
	WideCharToMultiByte( CP_ACP, 0, wstr, -1, str, len, NULL, NULL );
	return str;
}

// 设置 环境变量 类型值
void SetValue( WCHAR *varName, _int64 inValue, BOOL needINT )
{
	WCHAR varValue[MAX_PATH / 4];

	// 判断传入数值要打印成的类型
	if( needINT == TRUE )
	{
		swprintf( varValue, L"%lld", inValue );
	}
	else
	{
		swprintf( varValue, L"%.12G", *( ( double * )&inValue ) );
	}

	// 进行赋值
	BakSetEnvironmentVariableW( varName, varValue );
}

// 申明要引用的函数原型
#pragma warning( push )
extern "C"
{
	// 变量 赋值
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
	// 地址赋值
	int ispr( wchar_t* _String, const wchar_t * _Format, ... )
	{
		va_list _Arglist;
		_crt_va_start( _Arglist, _Format );
		int _Ret = _vswprintf( _String, _Format, _Arglist );
		_crt_va_end( _Arglist );
		return _Ret;
	}

	// 变量填充
	BOOL ifill( void* _inData, const wchar_t * _Format, ... )
	{
		va_list _Arglist;
		_crt_va_start( _Arglist, _Format );

		BYTE* pb = ( BYTE * )_inData;
		wchar_t* p = ( wchar_t * )_Format;
		while( *p )
		{
			//解析 SET 赋值类型
			switch( *p )
			{
			case L'*':
			case L'~':
				{
					if( *( p + 1 ) == L'S' )
					{
						wchar_t* tmpArg = ( wchar_t * ) _crt_va_arg( _Arglist, intptr_t );
						// +1 为了包含末尾的结束符 L'\0'
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
				// 指针后移
				pb += _wtoi( p + 1 );
				break;

			case L'-':
				// 指针前移
				pb -= _wtoi( p + 1 );
				break;

			default:
				// 无法识别的标识符
				return FALSE;
			}

			p += 2;
		}

		_crt_va_end( _Arglist );
		return TRUE;
	}

	// 变量输出
	BOOL iout( void* _inData, const wchar_t * _Format, ... )
	{
		va_list _Arglist;
		_crt_va_start( _Arglist, _Format );

		BYTE* pb = ( BYTE * )_inData;
		wchar_t* p = ( wchar_t * )_Format;
		while( *p )
		{
			//解析 SET 赋值类型
			switch( *p )
			{
			case L'*':
			{
				if( *( p + 1 ) == L'S' )
				{
					wchar_t* tmpArg = _crt_va_arg( _Arglist, wchar_t* );
					wchar_t* tmpStr = ( wchar_t* ) pb;

					// +1 为了包含末尾的结束符 L'\0'
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

			// 返回双精度浮点
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
				// 指针后移
				pb += _wtoi( p + 1 );
				break;

			case L'-':
				// 指针前移
				pb -= _wtoi( p + 1 );
				break;

			default:
				// 无法识别的标识符
				return FALSE;
			}

			p += 2;
		}

		_crt_va_end( _Arglist );
		return TRUE;
	}

}
#pragma warning( pop )

// FunCall 汇编函数
#ifdef  _WIN64
	/*
		;64位汇编 仅在单独的asm文件中方可编译, 不能内联
		;intptr_t  FunCall64( void* hProc, intptr_t* DLLParam, int DLLParamNum, int needINT )
		;CALL 64 APL, MADE BY SLIMAY 2021.09.24

		.CODE 
		FunCall64 PROC
			;  函数地址     传参数组     传参数目     传参模式
			;intptr_t* hProc, void* DLLParam, int DLLParamNum, int needINT

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
	*/
#else
_int64  FunCall32( void* hProc, intptr_t* DLLParam, int DLLParamNum, int needINT )
{
	union
	{
		_int64  retInt64;
		int     retInt[2];
	} RetInt;
	// 返回值容器清零
	RetInt.retInt64 = 0;

	// ESP备份容器, 实现兼容调用stdcall 和 cdecl
	int bakESP = 0;

	// 使用内联汇编, 低效稳定
    __asm
    {
		;备份栈帧
		mov bakESP,	esp

		;获取输入的参数
        mov		ebx, dword ptr [DLLParam]
        mov		ecx, dword ptr [DLLParamNum]
        dec		ecx 
		;计算出 传参数组 末尾指针
		lea		ebx, [ebx + ecx *4h]


	CYC: 
		;倒序 取出参数
		mov		eax, dword ptr [ebx]
		;参数 指针前移
		sub		ebx, 4
		;压栈
		push	eax 
		dec		ecx
		; 不为负值，则参数循环压栈
		jns		CYC                

		;调用函数, 执行call过程
        call dword ptr [hProc]

		;如果返回模式为真, 输出整型指针
		mov		ecx, dword ptr [needINT]
		cmp     ecx, 1
		je      FUNINT
		;返回浮点值
        fstp	RetInt.retInt64;
		jmp		FUNEND

	FUNINT:
        mov		RetInt.retInt[0], eax

	FUNEND:
		;针对 _cdecl 类型函数的call,由上级调用函数也就是FunCall32 负责 清理堆栈
		;恢复栈帧
		mov		esp,	bakESP
    }

	// 返回结果
	return (RetInt.retInt64);
}
#endif

// 参数解析
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

			// 最多只接受 MAX_ARGV_SIZE 个参数切分
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

// 解析核心, 必须是WINAPI型, 才能hook成功
BOOL  WINAPI  ICMDCore( WCHAR* varName, WCHAR* varContent )
{
	// 设置call 模式 默认值
	BOOL callMODE = TRUE;
	BOOL needINT  = TRUE;
	BOOL isISET   = FALSE;
	BOOL isISETP  = FALSE;

	//解析 SET 赋值类型
	switch( *varName )
	{
	case L'*':
		//返回常规整形
		needINT = TRUE;
		varName ++;
		break;

	case L'~':
		//返回双精浮点
		needINT = FALSE;
		varName ++;
		break;

	default:
		//归属 SET赋值
		BakSetEnvironmentVariableW( varName, varContent );
		return FALSE;
	}

	// 去除 赋值变量名 的前空格
	while( * varName == L' ' || * varName == L'\t' )
	{
		varName ++;
	}
	// 去除 赋值变量名 的后空格
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

	// 去除 赋值文本   的前空格
	while( * varContent == L' ' || * varContent == L'\t' )
	{
		varContent ++;
	}

	// 拟化命令行参数
	int DLLargc = 0;
	WCHAR** DLLargv = CommandLineToArgvW2( varContent, &DLLargc );

	// 参数不足, 或者参数超过64个,直接罢工
	if( DLLargc < 1 || DLLargc > MAX_ARGV_SIZE )
	{

		return FALSE;
	}

	// 要call的函数指针
	void* hProc = NULL;

	// 如果是自定义命令函数, 则不进行call 调用, 直接指向自定义命令
	if( wcsicmp( DLLargv[0], L"ILOAD" ) == 0 )
	{
		load_lib_size = 0;
		for( int i = 1; i < DLLargc; i++ )
		{
			// 获取 可执行 模块句柄
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

		// 替换成目标函数
		hProc = ( void * )iset;
	}
	else if( wcsicmp( DLLargv[0], L"ISPR" ) == 0 )
	{
		if( DLLargc == 1 )
		{
			return FALSE;
		}

		// 替换成目标函数
		hProc = ( void * )ispr;
	}
	else if( wcsicmp( DLLargv[0], L"IOUT" ) == 0 )
	{
		if( DLLargc == 1 )
		{
			return FALSE;
		}

		// 替换成目标函数
		hProc = ( void * )iout;
	}
	else if( wcsicmp( DLLargv[0], L"IFILL" ) == 0 )
	{
		if( DLLargc == 1 )
		{
			return FALSE;
		}

		// 替换成目标函数
		hProc = ( void * )ifill;
	}


	// 模块句柄
	HMODULE hmodDLL = NULL;
	if( hProc == NULL )
	{
		// 首先使用快速hash法查找 call 函数地址
		for( int i = 0; i < MAX_HASH_SIZE; i++ )
		{
			int hashFunIndex = ( hash_pointer - i ) + MAX_HASH_SIZE;
			hashFunIndex %= MAX_HASH_SIZE;
			// 先验证 首词是否匹配
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

	// 如果没有找到, 则使用循环遍历每个加载模块, 查找该函数名对应的地址
	if( hProc == NULL )
	{
		for( int i = 0; i < load_lib_size; i++ )
		{
			// 获取可执行模块 句柄return TRUE;
			hmodDLL =  GetModuleHandleW( load_lib_name[i] );

			// WCSToSTR
			CHAR funName[MAX_PATH];
			WCS2STR( DLLargv[0], funName );

			// 获取要 call 的函数地址
			hProc = ( void* ) GetProcAddress( hmodDLL, funName );

			if( hProc != NULL )
			{
				// 找到后进行hash圈入栈
				hash_pointer ++;
				hash_pointer %= MAX_HASH_SIZE;
				wcscpy( hash_fun_name[hash_pointer], DLLargv[0] );
				hash_fun_addr[hash_pointer] = ( void* )hProc;
				break;
			}
		}
	}

	// 如果地址任然为空, 则查找函数失败, 直接报错
	if( hProc == NULL )
	{
		fwprintf( stderr, L"[ERROR]Can not load function '%s'\n", DLLargv[0] );
		return FALSE;
	}


	// WCSToSTR  (利用定长数组实现转化单宽字符串 ,无需释放)
	CHAR tmpBuff[MAX_PATH / 4][MAX_PATH * 4];
	int tmpBuffIndex = 0;

	// 浮点-整型 转化器
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


	// 传参指针 数组
	intptr_t DLLParam[ MAX_ARGV_SIZE ];
	int DLLParamNum = 0;

	// 将字符串参数 转化为 传递给汇编的参数
	int k = 0;
	while( k < DLLargc - 1 )
	{
		switch( DLLargv[k + 1][0] )
		{
		// 整型
		case TYPE_INT:
			DLLParam[DLLParamNum] = WTOI( DLLargv[k + 1] + 1 );
			break;

		// 浮点
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

		// 字符型
		case TYPE_CHAR:
			DLLParam[DLLParamNum] = ( intptr_t )( *( ( CHAR* )( DLLargv[k + 1] + 1 ) ) );
			break;

		// 字符串型
		case TYPE_STRING:
			// WCS2STR
			DLLParam[DLLParamNum] = ( intptr_t ) WCS2STR( DLLargv[k + 1] + 1,  tmpBuff[ tmpBuffIndex ++] );
			break;

		// WCHAR 字符, 字符串解析
		case TYPE_WSTRING:
			// 宽字符型
			if( *( DLLargv[k + 1] + 1 ) == TYPE_CHAR )
			{
				DLLParam[DLLParamNum] = ( intptr_t )( *( ( WCHAR* )( DLLargv[k + 1] + 2 ) ) );
			}
			// 字符串型
			else
			{
				DLLParam[DLLParamNum] = ( intptr_t )( DLLargv[k + 1] + 1 );
			}
			break;

		//没有标识符按 int或者 _INT64 处理,
		default:
			// 如果含有小数点则按double处理
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
					// 只有在首字符为0的时候才激活 16进制 转化
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


	// 参数从右往左压栈，第二个参数为 传参数组的地址, 第三个参数为 传参数组的长度
#ifdef  _WIN64
	_int64 varValue = FunCall64( hProc, DLLParam, DLLParamNum, needINT );
#else
	_int64 varValue = FunCall32( hProc, DLLParam, DLLParamNum, needINT );
#endif

	if( *varName == L'\0')
	{
		return FALSE;
	}

	// 执行标准赋值
	SetValue( varName, varValue, needINT );

	//设置错误号 返回值
	SetValue( L"errorlevel", ( int )GetLastError(), TRUE );

	return TRUE;
}

// 主函数开始
BOOL WINAPI DllMain( HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpvReserved )
{
	switch (ul_reason_for_call)
	{
	// 执行HOOK过程
	case DLL_PROCESS_ATTACH:
		{
			// 获取模块路径
			WCHAR processPath[MAX_PATH];
			GetModuleFileNameW( hModule, processPath, MAX_PATH );
			// 将自己载入内存运行
			LoadLibraryW( processPath );

			// 系统大于Win7, 则HOOK "kernelBase.dll"
			LPCWSTR hookDllName = ( GetNtVersionFloat() > 6.1001f ) ? ( L"kernelbase.dll" ) : ( L"kernel32.dll" );
			// 获取 库中函数 SetEnvironmentVariableW 地址
			uintptr_t hookAddress = ( uintptr_t )GetProcAddress( LoadLibraryW( hookDllName ), "SetEnvironmentVariableW" );

			// 备份原函数地址
			BakSetEnvironmentVariableW = ( PFNSETENVIRONMENTVARIABLE )hookAddress;
			// 将 SetEnvironmentVariableW IAT表设为 跳转至 自定义函数
			IATHook( (uintptr_t)hookAddress, (uintptr_t)ICMDCore );

			// 默认加载一些基础库
			ICMDCore( L"*", L"ILOAD  L\"USER32.DLL\" L\"KERNEL32.DLL\" L\"GDI32.DLL\" L\"GDIPLUS.DLL\" L\"MSVCRT.DLL\"" );
			DisableThreadLibraryCalls( hModule );
		}
		break;

	case DLL_PROCESS_DETACH:
		// 卸载 HOOK函数
		if(BakSetEnvironmentVariableW != NULL)
		{
			// 将 SetEnvironmentVariableW 恢复其原地址
			IATHook( (uintptr_t)ICMDCore, (uintptr_t)BakSetEnvironmentVariableW );
		}
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}

	return TRUE;
}
