/* passwd_dlg.c - Dialog boxes for Windows95/NT
 * Author:	Jörgen Karlsson - d93-jka@nada.kth.se
 * Date:	June 1996
 */

#ifdef WIN32	/* Visual C++ 4.0 (Windows95/NT) */
#include <Windows.h>
#include "passwd_dlg.h"
#include "Resource.h"
#define passwdBufSZ 64

char passwd[passwdBufSZ];

BOOL CALLBACK pwd_dialog_proc(HWND  hwndDlg, UINT  uMsg, WPARAM  wParam, LPARAM  lParam)
{
	switch(uMsg)
	{
		case WM_COMMAND: 
			switch(wParam)
			{
				case IDOK:
					if(!GetDlgItemText(hwndDlg,IDC_PASSWD_EDIT, passwd ,passwdBufSZ))
						EndDialog(hwndDlg, IDCANCEL);
				case IDCANCEL:
					EndDialog(hwndDlg, wParam);
				return TRUE;
			}
	}
	return FALSE;
}


/* return 0 if ok, 1 otherwise */
int pwd_dialog(char *buf, int size)
{
	int i;
	HWND wnd = GetActiveWindow();
	HANDLE hInst = GetModuleHandle("des");
	switch(DialogBox(hInst,MAKEINTRESOURCE(IDD_PASSWD_DIALOG),wnd,pwd_dialog_proc))
	{
	case IDOK:
		strcpy(buf,passwd);
		for(i=0; passwd[i] != '\0'; i++) passwd[i] = '\0';
		return 0;
	case IDCANCEL:
	default:
		for(i=0; passwd[i] != '\0'; i++) passwd[i] = '\0';
		return 1;
	}
}



#endif /* WIN32 */