#include <config.h>
#include "roken.h"
#include <psapi.h>

static DWORD
GetVersionInfo(CHAR *filename, CHAR *szOutput, DWORD dwOutput)
{
    DWORD dwVersionHandle;
    LPVOID pVersionInfo = 0;
    DWORD retval = 0;
    LPDWORD pLangInfo = 0;
    LPTSTR szVersion = 0;
    UINT len = 0;
    TCHAR szVerQ[] = TEXT("\\StringFileInfo\\12345678\\FileVersion");
    DWORD size = GetFileVersionInfoSize(filename, &dwVersionHandle);

    if (!size)
	return GetLastError();

    pVersionInfo = malloc(size);
    if (!pVersionInfo)
	return ERROR_NOT_ENOUGH_MEMORY;

    GetFileVersionInfo(filename, dwVersionHandle, size, pVersionInfo);
    if (retval = GetLastError())
	goto cleanup;

    VerQueryValue(pVersionInfo, TEXT("\\VarFileInfo\\Translation"),
		       (LPVOID*)&pLangInfo, &len);
    if (retval = GetLastError())
	goto cleanup;

    wsprintf(szVerQ,
	     TEXT("\\StringFileInfo\\%04x%04x\\FileVersion"),
	     LOWORD(*pLangInfo), HIWORD(*pLangInfo));

    VerQueryValue(pVersionInfo, szVerQ, (LPVOID*)&szVersion, &len);
    if (retval = GetLastError()) {
	/* try again with language 409 since the old binaries were tagged wrong */
	wsprintf(szVerQ,
		  TEXT("\\StringFileInfo\\0409%04x\\FileVersion"),
		  HIWORD(*pLangInfo));

	VerQueryValue(pVersionInfo, szVerQ, (LPVOID*)&szVersion, &len);
	if (retval = GetLastError())
	    goto cleanup;
    }
    snprintf(szOutput, dwOutput, TEXT("%s"), szVersion);
    szOutput[dwOutput - 1] = 0;

 cleanup:
    free(pVersionInfo);

    return retval;
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
win32_getLibraryVersion(const char *libname, char **outname, char **outversion)
{
    CHAR modVersion[128];
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;
    int success = -1;
    HINSTANCE hPSAPI;
    DWORD (WINAPI *pGetModuleFileNameExA)(HANDLE hProcess, HMODULE hModule, LPTSTR lpFilename, DWORD nSize);
    BOOL (WINAPI *pEnumProcessModules)(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded);

    if (outversion)
	*outversion = NULL;
    if (outname)
	*outname = NULL;

    hPSAPI = LoadLibrary("psapi");
    if ( hPSAPI == NULL )
	return -1;

    if (((FARPROC) pGetModuleFileNameExA =
	  GetProcAddress( hPSAPI, "GetModuleFileNameExA" )) == NULL ||
	 ((FARPROC) pEnumProcessModules =
	   GetProcAddress( hPSAPI, "EnumProcessModules" )) == NULL)
    {
	goto out;
    }

    // Get a list of all the modules in this process.
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			   FALSE, GetCurrentProcessId());

    if (pEnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
	for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
	{
	    char szModName[2048];

	    // Get the full path to the module's file.
	    if (pGetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName)))
	    {
		CHAR checkName[1024];
		lstrcpy(checkName, szModName);
		strlwr(checkName);

		if (strstr(checkName, libname)) {
		    if (GetVersionInfo(szModName, modVersion, sizeof(modVersion)) == 0) {
			success = 0;
			if (outversion)	{
			    *outversion = strdup(modVersion);
			    if (*outversion == NULL)
				success = -1;
			}
			if (outname)	{
			    *outname = strdup(szModName);
			    if (*outname == NULL)
				success = -1;
			}
		    }
		    break;
		}
	    }
	}
    }
    CloseHandle(hProcess);

  out:
    FreeLibrary(hPSAPI);
    return success;
}
