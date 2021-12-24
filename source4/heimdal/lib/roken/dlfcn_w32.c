/*
 * dlfcn-win32
 * Copyright (c) 2007 Ramiro Polla
 * Copyright (c) 2015 Tiancheng "Timothy" Gu
 * Copyright (c) 2019 Pali Rohár <pali.rohar@gmail.com>
 * Copyright (c) 2020 Ralf Habacker <ralf.habacker@freenet.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 * Copied from https://github.com/dlfcn-win32/dlfcn-win32 and modified only to
 * fit Heimdal's lib/roken.
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#ifdef _DEBUG
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _MSC_VER
/* https://docs.microsoft.com/en-us/cpp/intrinsics/returnaddress */
#pragma intrinsic(_ReturnAddress)
#else
/* https://gcc.gnu.org/onlinedocs/gcc/Return-Address.html */
#ifndef _ReturnAddress
#define _ReturnAddress() (__builtin_extract_return_addr(__builtin_return_address(0)))
#endif
#endif

#ifdef DLFCN_WIN32_SHARED
#define DLFCN_WIN32_EXPORTS
#endif
#include "dlfcn.h"

/* Note:
 * MSDN says these functions are not thread-safe. We make no efforts to have
 * any kind of thread safety.
 */

typedef struct local_object {
    HMODULE hModule;
    struct local_object *previous;
    struct local_object *next;
} local_object;

static local_object first_object;

/* These functions implement a double linked list for the local objects. */
static local_object *local_search( HMODULE hModule )
{
    local_object *pobject;

    if( hModule == NULL )
        return NULL;

    for( pobject = &first_object; pobject; pobject = pobject->next )
        if( pobject->hModule == hModule )
            return pobject;

    return NULL;
}

static BOOL local_add( HMODULE hModule )
{
    local_object *pobject;
    local_object *nobject;

    if( hModule == NULL )
        return TRUE;

    pobject = local_search( hModule );

    /* Do not add object again if it's already on the list */
    if( pobject )
        return TRUE;

    for( pobject = &first_object; pobject->next; pobject = pobject->next );

    nobject = (local_object*) malloc( sizeof( local_object ) );

    if( !nobject )
    {
        SetLastError( ERROR_NOT_ENOUGH_MEMORY );
        return FALSE;
    }

    pobject->next = nobject;
    nobject->next = NULL;
    nobject->previous = pobject;
    nobject->hModule = hModule;

    return TRUE;
}

static void local_rem( HMODULE hModule )
{
    local_object *pobject;

    if( hModule == NULL )
        return;

    pobject = local_search( hModule );

    if( !pobject )
        return;

    if( pobject->next )
        pobject->next->previous = pobject->previous;
    if( pobject->previous )
        pobject->previous->next = pobject->next;

    free( pobject );
}

/* POSIX says dlerror( ) doesn't have to be thread-safe, so we use one
 * static buffer.
 * MSDN says the buffer cannot be larger than 64K bytes, so we set it to
 * the limit.
 */
static char error_buffer[65535];
static BOOL error_occurred;

static void save_err_str( const char *str )
{
    DWORD dwMessageId;
    DWORD ret;
    size_t pos, len;

    dwMessageId = GetLastError( );

    if( dwMessageId == 0 )
        return;

    len = strlen( str );
    if( len > sizeof( error_buffer ) - 5 )
        len = sizeof( error_buffer ) - 5;

    /* Format error message to:
     * "<argument to function that failed>": <Windows localized error message>
      */
    pos = 0;
    error_buffer[pos++] = '"';
    memcpy( error_buffer+pos, str, len );
    pos += len;
    error_buffer[pos++] = '"';
    error_buffer[pos++] = ':';
    error_buffer[pos++] = ' ';

    ret = FormatMessageA( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwMessageId,
        MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
        error_buffer+pos, (DWORD) (sizeof(error_buffer)-pos), NULL );
    pos += ret;

    /* When FormatMessageA() fails it returns zero and does not touch buffer
     * so add trailing null byte */
    if( ret == 0 )
        error_buffer[pos] = '\0';

    if( pos > 1 )
    {
        /* POSIX says the string must not have trailing <newline> */
        if( error_buffer[pos-2] == '\r' && error_buffer[pos-1] == '\n' )
            error_buffer[pos-2] = '\0';
    }

    error_occurred = TRUE;
}

static void save_err_ptr_str( const void *ptr )
{
    char ptr_buf[2 + 2 * sizeof( ptr ) + 1];
    char num;
    size_t i;

    ptr_buf[0] = '0';
    ptr_buf[1] = 'x';

    for( i = 0; i < 2 * sizeof( ptr ); i++ )
    {
        num = ( ( (ULONG_PTR) ptr ) >> ( 8 * sizeof( ptr ) - 4 * ( i + 1 ) ) ) & 0xF;
        ptr_buf[2+i] = num + ( ( num < 0xA ) ? '0' : ( 'A' - 0xA ) );
    }

    ptr_buf[2 + 2 * sizeof( ptr )] = 0;

    save_err_str( ptr_buf );
}

/* Load Psapi.dll at runtime, this avoids linking caveat */
static BOOL MyEnumProcessModules( HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded )
{
    static BOOL (WINAPI *EnumProcessModulesPtr)(HANDLE, HMODULE *, DWORD, LPDWORD);
    HMODULE psapi;

    if( !EnumProcessModulesPtr )
    {
        psapi = LoadLibraryA( "Psapi.dll" );
        if( psapi )
            EnumProcessModulesPtr = (BOOL (WINAPI *)(HANDLE, HMODULE *, DWORD, LPDWORD)) GetProcAddress( psapi, "EnumProcessModules" );
        if( !EnumProcessModulesPtr )
            return 0;
    }

    return EnumProcessModulesPtr( hProcess, lphModule, cb, lpcbNeeded );
}

ROKEN_LIB_FUNCTION void * ROKEN_LIB_CALL
dlopen( const char *file, int mode )
{
    HMODULE hModule;
    UINT uMode;

    error_occurred = FALSE;

    /* Do not let Windows display the critical-error-handler message box */
    uMode = SetErrorMode( SEM_FAILCRITICALERRORS );

    if( file == 0 )
    {
        /* POSIX says that if the value of file is 0, a handle on a global
         * symbol object must be provided. That object must be able to access
         * all symbols from the original program file, and any objects loaded
         * with the RTLD_GLOBAL flag.
         * The return value from GetModuleHandle( ) allows us to retrieve
         * symbols only from the original program file. EnumProcessModules() is
         * used to access symbols from other libraries. For objects loaded
         * with the RTLD_LOCAL flag, we create our own list later on. They are
         * excluded from EnumProcessModules() iteration.
         */
        hModule = GetModuleHandle( NULL );

        if( !hModule )
            save_err_str( "(null)" );
    }
    else
    {
        HANDLE hCurrentProc;
        DWORD dwProcModsBefore, dwProcModsAfter;
        char lpFileName[MAX_PATH];
        size_t i, len;

        len = strlen( file );

        if( len >= sizeof( lpFileName ) )
        {
            SetLastError( ERROR_FILENAME_EXCED_RANGE );
            save_err_str( file );
            hModule = NULL;
        }
        else
        {
            /* MSDN says backslashes *must* be used instead of forward slashes. */
            for( i = 0; i < len; i++ )
            {
                if( file[i] == '/' )
                    lpFileName[i] = '\\';
                else
                    lpFileName[i] = file[i];
            }
            lpFileName[len] = '\0';

            hCurrentProc = GetCurrentProcess( );

            if( MyEnumProcessModules( hCurrentProc, NULL, 0, &dwProcModsBefore ) == 0 )
                dwProcModsBefore = 0;

            /* POSIX says the search path is implementation-defined.
             * LOAD_WITH_ALTERED_SEARCH_PATH is used to make it behave more closely
             * to UNIX's search paths (start with system folders instead of current
             * folder).
             */
            hModule = LoadLibraryExA( lpFileName, NULL, LOAD_WITH_ALTERED_SEARCH_PATH );

            if( !hModule )
            {
                save_err_str( lpFileName );
            }
            else
            {
                if( MyEnumProcessModules( hCurrentProc, NULL, 0, &dwProcModsAfter ) == 0 )
                    dwProcModsAfter = 0;

                /* If the object was loaded with RTLD_LOCAL, add it to list of local
                 * objects, so that its symbols cannot be retrieved even if the handle for
                 * the original program file is passed. POSIX says that if the same
                 * file is specified in multiple invocations, and any of them are
                 * RTLD_GLOBAL, even if any further invocations use RTLD_LOCAL, the
                 * symbols will remain global. If number of loaded modules was not
                 * changed after calling LoadLibraryEx(), it means that library was
                 * already loaded.
                 */
                if( (mode & RTLD_LOCAL) && dwProcModsBefore != dwProcModsAfter )
                {
                    if( !local_add( hModule ) )
                    {
                        save_err_str( lpFileName );
                        FreeLibrary( hModule );
                        hModule = NULL;
                    }
                }
                else if( !(mode & RTLD_LOCAL) && dwProcModsBefore == dwProcModsAfter )
                {
                    local_rem( hModule );
                }
            }
        }
    }

    /* Return to previous state of the error-mode bit flags. */
    SetErrorMode( uMode );

    return (void *) hModule;
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
dlclose( void *handle )
{
    HMODULE hModule = (HMODULE) handle;
    BOOL ret;

    error_occurred = FALSE;

    ret = FreeLibrary( hModule );

    /* If the object was loaded with RTLD_LOCAL, remove it from list of local
     * objects.
     */
    if( ret )
        local_rem( hModule );
    else
        save_err_ptr_str( handle );

    /* dlclose's return value in inverted in relation to FreeLibrary's. */
    ret = !ret;

    return (int) ret;
}

__declspec(noinline) /* Needed for _ReturnAddress() */
ROKEN_LIB_FUNCTION DLSYM_RET_TYPE ROKEN_LIB_CALL
dlsym( void *handle, const char *name )
{
    FARPROC symbol;
    HMODULE hCaller;
    HMODULE hModule;
    HANDLE hCurrentProc;

    error_occurred = FALSE;

    symbol = NULL;
    hCaller = NULL;
    hModule = GetModuleHandle( NULL );
    hCurrentProc = GetCurrentProcess( );

    if( handle == RTLD_DEFAULT )
    {
        /* The symbol lookup happens in the normal global scope; that is,
         * a search for a symbol using this handle would find the same
         * definition as a direct use of this symbol in the program code.
         * So use same lookup procedure as when filename is NULL.
         */
        handle = hModule;
    }
    else if( handle == RTLD_NEXT )
    {
        /* Specifies the next object after this one that defines name.
         * This one refers to the object containing the invocation of dlsym().
         * The next object is the one found upon the application of a load
         * order symbol resolution algorithm. To get caller function of dlsym()
         * use _ReturnAddress() intrinsic. To get HMODULE of caller function
         * use standard GetModuleHandleExA() function.
         */
        if( !GetModuleHandleExA( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR) _ReturnAddress( ), &hCaller ) )
            goto end;
    }

    if( handle != RTLD_NEXT )
    {
        symbol = GetProcAddress( (HMODULE) handle, name );

        if( symbol != NULL )
            goto end;
    }

    /* If the handle for the original program file is passed, also search
     * in all globally loaded objects.
     */

    if( hModule == handle || handle == RTLD_NEXT )
    {
        HMODULE *modules;
        DWORD cbNeeded;
        DWORD dwSize;
        size_t i;

        /* GetModuleHandle( NULL ) only returns the current program file. So
         * if we want to get ALL loaded module including those in linked DLLs,
         * we have to use EnumProcessModules( ).
         */
        if( MyEnumProcessModules( hCurrentProc, NULL, 0, &dwSize ) != 0 )
        {
            modules = malloc( dwSize );
            if( modules )
            {
                if( MyEnumProcessModules( hCurrentProc, modules, dwSize, &cbNeeded ) != 0 && dwSize == cbNeeded )
                {
                    for( i = 0; i < dwSize / sizeof( HMODULE ); i++ )
                    {
                        if( handle == RTLD_NEXT && hCaller )
                        {
                            /* Next modules can be used for RTLD_NEXT */
                            if( hCaller == modules[i] )
                                hCaller = NULL;
                            continue;
                        }
                        if( local_search( modules[i] ) )
                            continue;
                        symbol = GetProcAddress( modules[i], name );
                        if( symbol != NULL )
                        {
                            free( modules );
                            goto end;
                        }
                    }

                }
                free( modules );
            }
            else
            {
                SetLastError( ERROR_NOT_ENOUGH_MEMORY );
                goto end;
            }
        }
    }

end:
    if( symbol == NULL )
    {
        if( GetLastError() == 0 )
            SetLastError( ERROR_PROC_NOT_FOUND );
        save_err_str( name );
    }

    return *(void **) (&symbol);
}

ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL
dlerror( void )
{
    /* If this is the second consecutive call to dlerror, return NULL */
    if( !error_occurred )
        return NULL;

    /* POSIX says that invoking dlerror( ) a second time, immediately following
     * a prior invocation, shall result in NULL being returned.
     */
    error_occurred = FALSE;

    return error_buffer;
}

/* See https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2
 * for details */

/* Get specific image section */
static BOOL get_image_section( HMODULE module, int index, void **ptr, DWORD *size )
{
    IMAGE_DOS_HEADER *dosHeader;
    IMAGE_OPTIONAL_HEADER *optionalHeader;

    dosHeader = (IMAGE_DOS_HEADER *) module;

    if( dosHeader->e_magic != 0x5A4D )
        return FALSE;

    optionalHeader = (IMAGE_OPTIONAL_HEADER *) ( (BYTE *) module + dosHeader->e_lfanew + 24 );

    if( optionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC )
        return FALSE;

    if( index < 0 || index > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR )
        return FALSE;

    if( optionalHeader->DataDirectory[index].Size == 0 || optionalHeader->DataDirectory[index].VirtualAddress == 0 )
        return FALSE;

    if( size != NULL )
        *size = optionalHeader->DataDirectory[index].Size;

    *ptr = (void *)( (BYTE *) module + optionalHeader->DataDirectory[index].VirtualAddress );

    return TRUE;
}

/* Return symbol name for a given address */
static const char *get_symbol_name( HMODULE module, IMAGE_IMPORT_DESCRIPTOR *iid, void *addr, void **func_address )
{
    int i;
    void *candidateAddr = NULL;
    const char *candidateName = NULL;
    BYTE *base = (BYTE *) module; /* Required to have correct calculations */

    for( i = 0; iid[i].Characteristics != 0 && iid[i].FirstThunk != 0; i++ )
    {
        IMAGE_THUNK_DATA *thunkILT = (IMAGE_THUNK_DATA *)( base + iid[i].Characteristics );
        IMAGE_THUNK_DATA *thunkIAT = (IMAGE_THUNK_DATA *)( base + iid[i].FirstThunk );

        for( ; thunkILT->u1.AddressOfData != 0; thunkILT++, thunkIAT++ )
        {
            IMAGE_IMPORT_BY_NAME *nameData;

            if( IMAGE_SNAP_BY_ORDINAL( thunkILT->u1.Ordinal ) )
                continue;

            if( (void *) thunkIAT->u1.Function > addr || candidateAddr >= (void *) thunkIAT->u1.Function )
                continue;

            candidateAddr = (void *) thunkIAT->u1.Function;
            nameData = (IMAGE_IMPORT_BY_NAME *)( base + (ULONG_PTR) thunkILT->u1.AddressOfData );
            candidateName = (const char *) nameData->Name;
        }
    }

    *func_address = candidateAddr;
    return candidateName;
}

static BOOL is_valid_address( void *addr )
{
    MEMORY_BASIC_INFORMATION info;
    SIZE_T result;

    if( addr == NULL )
        return FALSE;

    /* check valid pointer */
    result = VirtualQuery( addr, &info, sizeof( info ) );

    if( result == 0 || info.AllocationBase == NULL || info.AllocationProtect == 0 || info.AllocationProtect == PAGE_NOACCESS )
        return FALSE;

    return TRUE;
}

/* Return state if address points to an import thunk
 *
 * An import thunk is setup with a 'jmp' instruction followed by an
 * absolute address (32bit) or relative offset (64bit) pointing into
 * the import address table (iat), which is partially maintained by
 * the runtime linker.
 */
static BOOL is_import_thunk( void *addr )
{
    return *(short *) addr == 0x25ff ? TRUE : FALSE;
}

/* Return adress from the import address table (iat),
 * if the original address points to a thunk table entry.
 */
static void *get_address_from_import_address_table( void *iat, DWORD iat_size, void *addr )
{
    BYTE *thkp = (BYTE *) addr;
    /* Get offset from thunk table (after instruction 0xff 0x25)
     *   4018c8 <_VirtualQuery>: ff 25 4a 8a 00 00
     */
    ULONG offset = *(ULONG *)( thkp + 2 );
#ifdef _WIN64
    /* On 64 bit the offset is relative
     *      4018c8:   ff 25 4a 8a 00 00    jmpq    *0x8a4a(%rip)    # 40a318 <__imp_VirtualQuery>
     * And can be also negative (MSVC in WDK)
     *   100002f20:   ff 25 3a e1 ff ff    jmpq   *-0x1ec6(%rip)    # 0x100001060
     * So cast to signed LONG type
     */
    BYTE *ptr = (BYTE *)( thkp + 6 + (LONG) offset );
#else
    /* On 32 bit the offset is absolute
     *   4019b4:    ff 25 90 71 40 00    jmp    *0x40719
     */
    BYTE *ptr = (BYTE *) offset;
#endif

    if( !is_valid_address( ptr ) || ptr < (BYTE *) iat || ptr > (BYTE *) iat + iat_size )
        return NULL;

    return *(void **) ptr;
}

/* Holds module filename */
static char module_filename[2*MAX_PATH];

static BOOL fill_module_info( void *addr, Dl_info *info )
{
    HMODULE hModule;
    DWORD dwSize;

    if( !GetModuleHandleExA( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, addr, &hModule ) || hModule == NULL )
        return FALSE;

    dwSize = GetModuleFileNameA( hModule, module_filename, sizeof( module_filename ) );

    if( dwSize == 0 || dwSize == sizeof( module_filename ) )
        return FALSE;

    info->dli_fbase = (void *) hModule;
    info->dli_fname = module_filename;

    return TRUE;
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
dladdr( void *addr, Dl_info *info )
{
    void *realAddr, *funcAddress = NULL;
    HMODULE hModule;
    IMAGE_IMPORT_DESCRIPTOR *iid;
    DWORD iidSize = 0;

    if( addr == NULL || info == NULL )
        return 0;

    hModule = GetModuleHandleA( NULL );
    if( hModule == NULL )
        return 0;

    if( !is_valid_address( addr ) )
        return 0;

    realAddr = addr;

    if( !get_image_section( hModule, IMAGE_DIRECTORY_ENTRY_IMPORT, (void **) &iid, &iidSize ) )
        return 0;

    if( is_import_thunk( addr ) )
    {
        void *iat;
        void *iatAddr = NULL;
        DWORD iatSize = 0;

        if( !get_image_section( hModule, IMAGE_DIRECTORY_ENTRY_IAT, &iat, &iatSize ) )
        {
            /* Fallback for cases where the iat is not defined,
             * for example i586-mingw32msvc-gcc */
            if( iid == NULL || iid->Characteristics == 0 || iid->FirstThunk == 0 )
                return 0;

            iat = (void *)( (BYTE *) hModule + iid->FirstThunk );
            /* We assume that in this case iid and iat's are in linear order */
            iatSize = iidSize - (DWORD) ( (BYTE *) iat - (BYTE *) iid );
        }

        iatAddr = get_address_from_import_address_table( iat, iatSize, addr );
        if( iatAddr == NULL )
            return 0;

        realAddr = iatAddr;
    }

    if( !fill_module_info( realAddr, info ) )
        return 0;

    info->dli_sname = get_symbol_name( hModule, iid, realAddr, &funcAddress );

    info->dli_saddr = !info->dli_sname ? NULL : funcAddress ? funcAddress : realAddr;
    return 1;
}

#ifdef DLFCN_WIN32_SHARED
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
{
    (void) hinstDLL;
    (void) fdwReason;
    (void) lpvReserved;
    return TRUE;
}
#endif
