#include <Windows.h>

void msg(char *text)
{
	HWND wnd = GetActiveWindow();

	MessageBox(wnd, text, "KClient message", MB_OK|MB_APPLMODAL);
}

BOOL   WINAPI   DllMain (HANDLE hInst, 
                        ULONG reason,
                        LPVOID lpReserved)
{
	WORD wVersionRequested; 
	WSADATA wsaData; 
	int err; 
	switch(reason){
	case DLL_PROCESS_ATTACH:
			return FALSE;
		}
		break;
	case DLL_PROCESS_DETACH:
		WSACleanup();
	}

  	
	msg("Initializing krb4.dll OK");
	return TRUE;
}