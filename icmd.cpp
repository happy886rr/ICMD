#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

extern "C" HWND WINAPI GetConsoleWindow( void );

// 提升进程特权
BOOL EnablePrivilege( BOOL enable )
{
	HANDLE hToken = NULL;
	LUID luid;
	TOKEN_PRIVILEGES tp = {0};

	// 得到令牌句柄
	if( !OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_READ, &hToken ) )
	{
		return FALSE;
	}

	// 得到特权值

	if( !LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &luid ) )
	{
		return FALSE;
	}

	// 提升令牌句柄权限
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
	if( !AdjustTokenPrivileges( hToken, FALSE, &tp, 0, NULL, NULL ) )
		return FALSE;

	// 关闭令牌句柄
	CloseHandle( hToken );
	return TRUE;
}

// 注入DLL
BOOL InjectDll( HANDLE process, CHAR* dllPath )
{
	DWORD dllPathSize = 0;
	void* remoteMemory = NULL;
	HANDLE remoteThread = NULL;
	DWORD remoteModule = 0;

	dllPathSize = ( ( DWORD )strlen( dllPath ) + 1 ) * sizeof( CHAR );

	// 申请内存用来存放DLL路径
	remoteMemory = VirtualAllocEx( process, NULL, dllPathSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	if( remoteMemory == NULL )
	{
		return FALSE;
	}

	// 写入DLL路径
	if( !WriteProcessMemory( process, remoteMemory, dllPath, dllPathSize, NULL ) )
	{
		return FALSE;
	}

	// 创建远线程调用LoadLibrary
	remoteThread = CreateRemoteThread( process, NULL, 0, ( LPTHREAD_START_ROUTINE )LoadLibraryA, remoteMemory, 0, NULL );
	if( remoteThread == NULL )
	{
		return FALSE;
	}

	// 等待远线程结束
	WaitForSingleObject( remoteThread, INFINITE );
	// 取DLL在目标进程的句柄
	GetExitCodeThread( remoteThread, &remoteModule );

	// 释放
	CloseHandle( remoteThread );
	VirtualFreeEx( process, remoteMemory, dllPathSize, MEM_DECOMMIT );
	return TRUE;
}

// 主函数
int main( int argc, char** argv )
{
	CHAR dllPath[MAX_PATH];
	HANDLE process = NULL;
	HWND hwnd;
	DWORD pid;
	FILE* fp;
	FLOAT verFloat = 0.0f;

	// 接受 1个参数, 2个参数, 则参数argv[1]为要注入的dll名称 
	if( argc != 1 && argc != 2 )
	{
		printf("usage: icmd64 [*.dll]\n");
		exit( 1 );
	}

	// 提升权限
	EnablePrivilege( TRUE );

	// 获取当前进程句柄
	hwnd = GetConsoleWindow();
	GetWindowThreadProcessId( hwnd, &pid );
	process = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );

	if( process == NULL )
	{
		printf( "Open cmd process failed.\n" );
		return 1;
	}

	// 获取 DLL路径
	GetModuleFileNameA( GetModuleHandle(NULL), dllPath, MAX_PATH );
	char* pLastPathMark = strrchr(dllPath, '\\');
	if( pLastPathMark )
	{
		*pLastPathMark = 0;
	}

	strcat( dllPath, "\\");
#ifdef  _WIN64
	strcat( dllPath,  (argc == 2)?(argv[1]):("icmd64.dll") );
#else
	strcat( dllPath,  (argc == 2)?(argv[1]):("icmd32.dll") );
#endif

	// 注入 DLL文件
	if( InjectDll( process, dllPath ) == FALSE )
	{
		printf( "Inject \"%s\" failed.\n", dllPath );
		CloseHandle( process );
		return 1;
	}

	// 关闭进程
	CloseHandle( process );
	return 0;
}

