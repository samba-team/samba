/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) John H Terpstra 1996-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   Copyright (C) Paul Ashton 1998 - 1999
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef _SMB_MACROS_H
#define _SMB_MACROS_H

/* Misc bit macros */
#define BOOLSTR(b) ((b) ? "Yes" : "No")
#define BITSETB(ptr,bit) ((((char *)ptr)[0] & (1<<(bit)))!=0)
#define BITSETW(ptr,bit) ((SVAL(ptr,0) & (1<<(bit)))!=0)

/* for readability... */
#define IS_DOS_READONLY(test_mode) (((test_mode) & aRONLY) != 0)
#define IS_DOS_DIR(test_mode)      (((test_mode) & aDIR) != 0)
#define IS_DOS_ARCHIVE(test_mode)  (((test_mode) & aARCH) != 0)
#define IS_DOS_SYSTEM(test_mode)   (((test_mode) & aSYSTEM) != 0)
#define IS_DOS_HIDDEN(test_mode)   (((test_mode) & aHIDDEN) != 0)

#ifndef SAFE_FREE /* Oh no this is also defined in tdb.h */

/**
 * Free memory if the pointer and zero the pointer.
 *
 * @note You are explicitly allowed to pass NULL pointers -- they will
 * always be ignored.
 **/
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)
#endif

/* zero a structure */
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

/* zero a structure given a pointer to the structure */
#define ZERO_STRUCTP(x) do { if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); } while(0)

/* zero a structure given a pointer to the structure - no zero check */
#define ZERO_STRUCTPN(x) memset((char *)(x), 0, sizeof(*(x)))

/* zero an array - note that sizeof(array) must work - ie. it must not be a 
   pointer */
#define ZERO_ARRAY(x) memset((char *)(x), 0, sizeof(x))

/* pointer difference macro */
#define PTR_DIFF(p1,p2) ((ptrdiff_t)(((const char *)(p1)) - (const char *)(p2)))

/* work out how many elements there are in a static array */
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

/* assert macros */
#define SMB_ASSERT(b) ((b)?(void)0: \
        (DEBUG(0,("PANIC: assert failed at %s(%d)\n", \
		 __FILE__, __LINE__)), smb_panic("assert failed")))
#define SMB_ASSERT_ARRAY(a,n) SMB_ASSERT((sizeof(a)/sizeof((a)[0])) >= (n))

/* these are useful macros for checking validity of handles */
#define OPEN_FSP(fsp)    ((fsp) && !(fsp)->is_directory)
#define OPEN_CONN(conn)    ((conn) && (conn)->open)
#define IS_IPC(conn)       ((conn) && (conn)->ipc)
#define IS_PRINT(conn)       ((conn) && (conn)->printer)
#define FSP_BELONGS_CONN(fsp,conn) do {\
			extern struct current_user current_user;\
			if (!((fsp) && (conn) && ((conn)==(fsp)->conn) && (current_user.vuid==(fsp)->vuid))) \
				return(ERROR_DOS(ERRDOS,ERRbadfid));\
			} while(0)

#define FNUM_OK(fsp,c) (OPEN_FSP(fsp) && (c)==(fsp)->conn && current_user.vuid==(fsp)->vuid)

#define CHECK_FSP(fsp,conn) do {\
			extern struct current_user current_user;\
			if (!FNUM_OK(fsp,conn)) \
				return(ERROR_DOS(ERRDOS,ERRbadfid)); \
			else if((fsp)->fd == -1) \
				return(ERROR_DOS(ERRDOS,ERRbadaccess));\
			} while(0)

#define CHECK_READ(fsp) if (!(fsp)->can_read) \
				return(ERROR_DOS(ERRDOS,ERRbadaccess))
#define CHECK_WRITE(fsp) if (!(fsp)->can_write) \
				return(ERROR_DOS(ERRDOS,ERRbadaccess))

#define CHECK_ERROR(fsp) if (HAS_CACHED_ERROR(fsp)) \
				return(CACHED_ERROR(fsp))

#define ERROR_WAS_LOCK_DENIED(status) (NT_STATUS_EQUAL((status), NT_STATUS_LOCK_NOT_GRANTED) || \
				NT_STATUS_EQUAL((status), NT_STATUS_FILE_LOCK_CONFLICT) )

/* the service number for the [globals] defaults */ 
#define GLOBAL_SECTION_SNUM	(-1)
/* translates a connection number into a service number */
#define SNUM(conn)         	((conn)?(conn)->service:GLOBAL_SECTION_SNUM)


/* access various service details */
#define SERVICE(snum)      (lp_servicename(snum))
#define PRINTERNAME(snum)  (lp_printername(snum))
#define CAN_WRITE(conn)    (!conn->read_only)
#define VALID_SNUM(snum)   (lp_snum_ok(snum))
#define GUEST_OK(snum)     (VALID_SNUM(snum) && lp_guest_ok(snum))
#define GUEST_ONLY(snum)   (VALID_SNUM(snum) && lp_guest_only(snum))
#define CAN_SETDIR(snum)   (!lp_no_set_dir(snum))
#define CAN_PRINT(conn)    ((conn) && lp_print_ok((conn)->service))
#define MAP_HIDDEN(conn)   ((conn) && lp_map_hidden((conn)->service))
#define MAP_SYSTEM(conn)   ((conn) && lp_map_system((conn)->service))
#define MAP_ARCHIVE(conn)   ((conn) && lp_map_archive((conn)->service))
#define IS_HIDDEN_PATH(conn,path)  ((conn) && is_in_path((path),(conn)->hide_list))
#define IS_VETO_PATH(conn,path)  ((conn) && is_in_path((path),(conn)->veto_list))
#define IS_VETO_OPLOCK_PATH(conn,path)  ((conn) && is_in_path((path),(conn)->veto_oplock_list))

/* 
 * Used by the stat cache code to check if a returned
 * stat structure is valid.
 */

#define VALID_STAT(st) ((st).st_nlink != 0)  
#define VALID_STAT_OF_DIR(st) (VALID_STAT(st) && S_ISDIR((st).st_mode))

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#ifndef ABS
#define ABS(a) ((a)>0?(a):(-(a)))
#endif

/* Macros to get at offsets within smb_lkrng and smb_unlkrng
   structures. We cannot define these as actual structures
   due to possible differences in structure packing
   on different machines/compilers. */

#define SMB_LPID_OFFSET(indx) (10 * (indx))
#define SMB_LKOFF_OFFSET(indx) ( 2 + (10 * (indx)))
#define SMB_LKLEN_OFFSET(indx) ( 6 + (10 * (indx)))
#define SMB_LARGE_LPID_OFFSET(indx) (20 * (indx))
#define SMB_LARGE_LKOFF_OFFSET_HIGH(indx) (4 + (20 * (indx)))
#define SMB_LARGE_LKOFF_OFFSET_LOW(indx) (8 + (20 * (indx)))
#define SMB_LARGE_LKLEN_OFFSET_HIGH(indx) (12 + (20 * (indx)))
#define SMB_LARGE_LKLEN_OFFSET_LOW(indx) (16 + (20 * (indx)))

/* Macro to cache an error in a write_bmpx_struct */
#define CACHE_ERROR(w,c,e) ((w)->wr_errclass = (c), (w)->wr_error = (e), \
                w->wr_discard = True, -1)
/* Macro to test if an error has been cached for this fnum */
#define HAS_CACHED_ERROR(fsp) ((fsp)->wbmpx_ptr && \
                (fsp)->wbmpx_ptr->wr_discard)
/* Macro to turn the cached error into an error packet */
#define CACHED_ERROR(fsp) cached_error_packet(outbuf,fsp,__LINE__,__FILE__)

/* these are the datagram types */
#define DGRAM_DIRECT_UNIQUE 0x10

#define ERROR_DOS(class,code) error_packet(outbuf,NT_STATUS_OK,class,code,__LINE__,__FILE__)
#define ERROR_NT(status) error_packet(outbuf,status,0,0,__LINE__,__FILE__)
#define ERROR_BOTH(status,class,code) error_packet(outbuf,status,class,code,__LINE__,__FILE__)

/* this is how errors are generated */
#define UNIXERROR(defclass,deferror) unix_error_packet(outbuf,defclass,deferror,__LINE__,__FILE__)

#define SMB_ROUNDUP(x,r) ( ((x)%(r)) ? ( (((x)+(r))/(r))*(r) ) : (x))

/* Extra macros added by Ying Chen at IBM - speed increase by inlining. */
#define smb_buf(buf) (((char *)(buf)) + smb_size + CVAL(buf,smb_wct)*2)
#define smb_buflen(buf) (SVAL(buf,smb_vwv0 + (int)CVAL(buf, smb_wct)*2))

/* the remaining number of bytes in smb buffer 'buf' from pointer 'p'. */
#define smb_bufrem(buf, p) (smb_buflen(buf)-PTR_DIFF(p, smb_buf(buf)))

/* Note that chain_size must be available as an extern int to this macro. */
#define smb_offset(p,buf) (PTR_DIFF(p,buf+4) + chain_size)

#define smb_len(buf) (PVAL(buf,3)|(PVAL(buf,2)<<8)|((PVAL(buf,1)&1)<<16))
#define _smb_setlen(buf,len) do { buf[0] = 0; buf[1] = (len&0x10000)>>16; \
        buf[2] = (len&0xFF00)>>8; buf[3] = len&0xFF; } while (0)

/*******************************************************************
find the difference in milliseconds between two struct timeval
values
********************************************************************/

#define TvalDiff(tvalold,tvalnew) \
  (((tvalnew)->tv_sec - (tvalold)->tv_sec)*1000 +  \
	 ((int)(tvalnew)->tv_usec - (int)(tvalold)->tv_usec)/1000)

/****************************************************************************
true if two IP addresses are equal
****************************************************************************/

#define ip_equal(ip1,ip2) ((ip1).s_addr == (ip2).s_addr)
#define ip_service_equal(ip1,ip2) ( ((ip1).ip.s_addr == (ip2).ip.s_addr) && ((ip1).port == (ip2).port) )

/*****************************************************************
 splits out the last subkey of a key
 *****************************************************************/  

#define reg_get_subkey(full_keyname, key_name, subkey_name) \
	split_at_last_component(full_keyname, key_name, '\\', subkey_name)

/****************************************************************************
 Used by dptr_zero.
****************************************************************************/

#define DPTR_MASK ((uint32)(((uint32)1)<<31))

/****************************************************************************
 Return True if the offset is at zero.
****************************************************************************/

#define dptr_zero(buf) ((IVAL(buf,1)&~DPTR_MASK) == 0)

/*******************************************************************
copy an IP address from one buffer to another
********************************************************************/

#define putip(dest,src) memcpy(dest,src,4)

/*******************************************************************
 Return True if a server has CIFS UNIX capabilities.
********************************************************************/

#define SERVER_HAS_UNIX_CIFS(c) ((c)->capabilities & CAP_UNIX)

/****************************************************************************
 Make a filename into unix format.
****************************************************************************/

#define IS_DIRECTORY_SEP(c) ((c) == '\\' || (c) == '/')
#define unix_format(fname) string_replace(fname,'\\','/')
#define unix_format_w(fname) string_replace_w(fname, UCS2_CHAR('\\'), UCS2_CHAR('/'))

/****************************************************************************
 Make a file into DOS format.
****************************************************************************/

#define dos_format(fname) string_replace(fname,'/','\\')

/*****************************************************************************
 Check to see if we are a DO for this domain
*****************************************************************************/

#define IS_DC  (lp_server_role()==ROLE_DOMAIN_PDC || lp_server_role()==ROLE_DOMAIN_BDC) 

#endif /* _SMB_MACROS_H */
