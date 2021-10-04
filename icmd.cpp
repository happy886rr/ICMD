#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

extern "C" HWND WINAPI GetConsoleWindow( void );

// ����������Ȩ
BOOL EnablePrivilege( BOOL enable )
{
	HANDLE hToken = NULL;
	LUID luid;
	TOKEN_PRIVILEGES tp = {0};

	// �õ����ƾ��
	if( !OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_READ, &hToken ) )
	{
		return FALSE;
	}

	// �õ���Ȩֵ

	if( !LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &luid ) )
	{
		return FALSE;
	}

	// �������ƾ��Ȩ��
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
	if( !AdjustTokenPrivileges( hToken, FALSE, &tp, 0, NULL, NULL ) )
		return FALSE;

	// �ر����ƾ��
	CloseHandle( hToken );
	return TRUE;
}

// ע��DLL
BOOL InjectDll( HANDLE process, CHAR* dllPath )
{
	DWORD dllPathSize = 0;
	void* remoteMemory = NULL;
	HANDLE remoteThread = NULL;
	DWORD remoteModule = 0;

	dllPathSize = ( ( DWORD )strlen( dllPath ) + 1 ) * sizeof( CHAR );

	// �����ڴ��������DLL·��
	remoteMemory = VirtualAllocEx( process, NULL, dllPathSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	if( remoteMemory == NULL )
	{
		return FALSE;
	}

	// д��DLL·��
	if( !WriteProcessMemory( process, remoteMemory, dllPath, dllPathSize, NULL ) )
	{
		return FALSE;
	}

	// ����Զ�̵߳���LoadLibrary
	remoteThread = CreateRemoteThread( process, NULL, 0, ( LPTHREAD_START_ROUTINE )LoadLibraryA, remoteMemory, 0, NULL );
	if( remoteThread == NULL )
	{
		return FALSE;
	}

	// �ȴ�Զ�߳̽���
	WaitForSingleObject( remoteThread, INFINITE );
	// ȡDLL��Ŀ����̵ľ��
	GetExitCodeThread( remoteThread, &remoteModule );

	// �ͷ�
	CloseHandle( remoteThread );
	VirtualFreeEx( process, remoteMemory, dllPathSize, MEM_DECOMMIT );
	return TRUE;
}

// ������
int main( int argc, char** argv )
{
	CHAR dllPath[MAX_PATH];
	HANDLE process = NULL;
	HWND hwnd;
	DWORD pid;
	FILE* fp;
	FLOAT verFloat = 0.0f;

	// ���� 1������, 2������, �����argv[1]ΪҪע���dll���� 
	if( argc != 1 && argc != 2 )
	{
		printf("usage: icmd64 [*.dll]\n");
		exit( 1 );
	}

	// ����Ȩ��
	EnablePrivilege( TRUE );

	// ��ȡ��ǰ���̾��
	hwnd = GetConsoleWindow();
	GetWindowThreadProcessId( hwnd, &pid );
	process = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );

	if( process == NULL )
	{
		printf( "Open cmd process failed.\n" );
		return 1;
	}

	// ��ȡ DLL·��
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

	// ע�� DLL�ļ�
	if( InjectDll( process, dllPath ) == FALSE )
	{
		printf( "Inject \"%s\" failed.\n", dllPath );
		CloseHandle( process );
		return 1;
	}

	// �رս���
	CloseHandle( process );
	return 0;
}

