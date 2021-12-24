/*
 * Copyright (c) 2018-2019, AuriStor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _VERSIONSUPPORT_H_
#define _VERSIONSUPPORT_H_ 1

/*
 * IsWindowsVersionOrGreater() is provided by Windows SDK 8.1 or greater.
 * As AuriStorFS supports building with SDK 7.0 and greater we must
 * provide our own.  VerifyVersionInfoW() is present on Windows XP and
 * later.
 */

#ifndef _WIN32_WINNT_WIN7
#define _WIN32_WINNT_WIN7     0x0601
#endif

#ifndef _WIN32_WINNT_WIN8
#define _WIN32_WINNT_WIN8     0x0602
#endif

#ifndef _WIN32_WINNT_WINBLUE
#define _WIN32_WINNT_WINBLUE  0x0603
#endif

/* Based upon VersionHelpers.h */
FORCEINLINE BOOL
IsWindowsVersionOrGreater(WORD wMajorVersion,
			  WORD wMinorVersion,
			  WORD wServicePackMajor)
{
    OSVERSIONINFOEXW osvi;
    DWORDLONG        dwlConditionMask = 0;

    dwlConditionMask = VerSetConditionMask(dwlConditionMask,
					   VER_MAJORVERSION,
					   VER_GREATER_EQUAL);
    dwlConditionMask = VerSetConditionMask(dwlConditionMask,
					   VER_MINORVERSION,
					   VER_GREATER_EQUAL);
    dwlConditionMask = VerSetConditionMask(dwlConditionMask,
					   VER_SERVICEPACKMAJOR,
					   VER_GREATER_EQUAL);

    memset(&osvi, 0, sizeof(OSVERSIONINFOEXW));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
    osvi.dwMajorVersion = wMajorVersion;
    osvi.dwMinorVersion = wMinorVersion;
    osvi.wServicePackMajor = wServicePackMajor;

    return VerifyVersionInfoW(&osvi,
			      (VER_MAJORVERSION |
			       VER_MINORVERSION |
			       VER_SERVICEPACKMAJOR),
			      dwlConditionMask);
}

FORCEINLINE BOOL
IsWindowsXPOrGreater(VOID)
{
    return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINXP),
				     LOBYTE(_WIN32_WINNT_WINXP),
				     0);
}

FORCEINLINE BOOL
IsWindows7OrGreater(VOID)
{
    return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN7),
				     LOBYTE(_WIN32_WINNT_WIN7),
				     0);
}

FORCEINLINE BOOL
IsWindows8OrGreater(VOID)
{
    return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN8),
				     LOBYTE(_WIN32_WINNT_WIN8),
				     0);
}

FORCEINLINE BOOL
IsWindows8Point1OrGreater(VOID)
{
    return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINBLUE),
				     LOBYTE(_WIN32_WINNT_WINBLUE),
				     0);
}

#define IS_WINDOWS_VERSION_OR_GREATER_CACHED(fn)		\
								\
FORCEINLINE BOOL						\
fn##Cached(VOID)						\
{								\
    static LONG lIsVersionOrGreater = -1;			\
								\
    if (lIsVersionOrGreater == -1) {				\
	LONG lResult = fn();					\
	InterlockedCompareExchangeRelease(&lIsVersionOrGreater, \
					  lResult, -1);		\
    }								\
								\
    return lIsVersionOrGreater == 1;				\
}

IS_WINDOWS_VERSION_OR_GREATER_CACHED(IsWindowsXPOrGreater)
IS_WINDOWS_VERSION_OR_GREATER_CACHED(IsWindows7OrGreater)
IS_WINDOWS_VERSION_OR_GREATER_CACHED(IsWindows8OrGreater)
IS_WINDOWS_VERSION_OR_GREATER_CACHED(IsWindows8Point1OrGreater)

#endif /* _VERSIONSUPPORT_H_ */
