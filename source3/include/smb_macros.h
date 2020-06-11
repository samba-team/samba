/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) John H Terpstra 1996-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   Copyright (C) Paul Ashton 1998 - 1999

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _SMB_MACROS_H
#define _SMB_MACROS_H

/* Misc bit macros */
#define BOOLSTR(b) ((b) ? "Yes" : "No")
#define BITSETW(ptr,bit) ((SVAL(ptr,0) & (1<<(bit)))!=0)

/* for readability... */
#define IS_DOS_READONLY(test_mode) (((test_mode) & FILE_ATTRIBUTE_READONLY) != 0)
#define IS_DOS_DIR(test_mode)      (((test_mode) & FILE_ATTRIBUTE_DIRECTORY) != 0)
#define IS_DOS_ARCHIVE(test_mode)  (((test_mode) & FILE_ATTRIBUTE_ARCHIVE) != 0)
#define IS_DOS_SYSTEM(test_mode)   (((test_mode) & FILE_ATTRIBUTE_SYSTEM) != 0)
#define IS_DOS_HIDDEN(test_mode)   (((test_mode) & FILE_ATTRIBUTE_HIDDEN) != 0)

#define SMB_WARN(condition, message) \
    ((condition) ? (void)0 : \
     DEBUG(0, ("WARNING: %s: %s\n", #condition, message)))

#define SMB_ASSERT_ARRAY(a,n) SMB_ASSERT((sizeof(a)/sizeof((a)[0])) >= (n))

/* these are useful macros for checking validity of handles */
#define IS_IPC(conn)       ((conn) && (conn)->ipc)
#define IS_PRINT(conn)       ((conn) && (conn)->printer)

#define CHECK_READ(fsp,req) \
	(((fsp)->fh->fd != -1) && \
	 (((fsp)->fsp_flags.can_read) || \
	  ((req->flags2 & FLAGS2_READ_PERMIT_EXECUTE) && \
	   (fsp->access_mask & FILE_EXECUTE))))

/*
 * This is not documented in revision 49 of [MS-SMB2] but should be added in a
 * later revision (and torture test smb2.read.access as well as
 * smb2.ioctl_copy_chunk_bad_access against Server 2012R2 confirms this)
 *
 * If FILE_EXECUTE is granted to a handle then the SMB2 server acts as if
 * FILE_READ_DATA has also been granted. We must still keep the original granted
 * mask, because with ioctl requests, access checks are made on the file handle,
 * "below" the SMB2 server, and the object store below the SMB layer is not
 * aware of this arrangement (see smb2.ioctl.copy_chunk_bad_access torture
 * test).
 */
#define CHECK_READ_SMB2(fsp) \
	(((fsp)->fh->fd != -1) && \
	 (((fsp)->fsp_flags.can_read) || \
	  (fsp->access_mask & FILE_EXECUTE)))

/* An IOCTL readability check (validating read access
 * when the IOCTL code requires it)
 * http://social.technet.microsoft.com/wiki/contents/articles/24653.decoding-io-control-codes-ioctl-fsctl-and-deviceiocodes-with-table-of-known-values.aspx
 * ). On Windows servers, this is done by the IO manager, which is unaware of
 * the "if execute is granted then also grant read" arrangement.
 */
#define CHECK_READ_IOCTL(fsp) \
	(((fsp)->fh->fd != -1) && \
	 (((fsp)->fsp_flags.can_read)))

#define CHECK_WRITE(fsp) \
	((fsp)->fsp_flags.can_write && \
	 ((fsp)->fh->fd != -1))

#define ERROR_WAS_LOCK_DENIED(status) (NT_STATUS_EQUAL((status), NT_STATUS_LOCK_NOT_GRANTED) || \
				NT_STATUS_EQUAL((status), NT_STATUS_FILE_LOCK_CONFLICT) )

/* the service number for the [globals] defaults */ 
#define GLOBAL_SECTION_SNUM	(-1)
/* translates a connection number into a service number */
#define SNUM(conn)         	((conn)?(conn)->params->service:GLOBAL_SECTION_SNUM)


/* access various service details */
#define CAN_WRITE(conn)    (!conn->read_only)
#define VALID_SNUM(snum)   (lp_snum_ok(snum))
#define GUEST_OK(snum)     (VALID_SNUM(snum) && lp_guest_ok(snum))
#define GUEST_ONLY(snum)   (VALID_SNUM(snum) && lp_guest_only(snum))
#define CAN_PRINT(conn)    ((conn) && lp_printable(SNUM(conn)))
#define MAP_HIDDEN(conn)   ((conn) && lp_map_hidden(SNUM(conn)))
#define MAP_SYSTEM(conn)   ((conn) && lp_map_system(SNUM(conn)))
#define MAP_ARCHIVE(conn)   ((conn) && lp_map_archive(SNUM(conn)))
#define IS_HIDDEN_PATH(conn,path)  ((conn) && is_in_path((path),(conn)->hide_list,(conn)->case_sensitive))
#define IS_VETO_PATH(conn,path)  ((conn) && is_in_path((path),(conn)->veto_list,(conn)->case_sensitive))
#define IS_VETO_OPLOCK_PATH(conn,path)  ((conn) && is_in_path((path),(conn)->veto_oplock_list,(conn)->case_sensitive))

/* 
 * Used by the stat cache code to check if a returned
 * stat structure is valid.
 */

#define VALID_STAT(st) ((st).st_ex_nlink != 0)
#define VALID_STAT_OF_DIR(st) (VALID_STAT(st) && S_ISDIR((st).st_ex_mode))
#define SET_STAT_INVALID(st) ((st).st_ex_nlink = 0)

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

#define ERROR_NT(status) error_packet(outbuf,0,0,status,__LINE__,__FILE__)
#define ERROR_BOTH(status,class,code) error_packet(outbuf,class,code,status,__LINE__,__FILE__)

#define reply_nterror(req,status) reply_nt_error(req,status,__LINE__,__FILE__)
#define reply_force_doserror(req,eclass,ecode) reply_force_dos_error(req,eclass,ecode,__LINE__,__FILE__)
#define reply_botherror(req,status,eclass,ecode) reply_both_error(req,eclass,ecode,status,__LINE__,__FILE__)

#if 0
/* defined in IDL */
/* these are the datagram types */
#define DGRAM_DIRECT_UNIQUE 0x10
#endif

#define SMB_ROUNDUP(x,r) ( ((x)%(r)) ? ( (((x)+(r))/(r))*(r) ) : (x))

/* Extra macros added by Ying Chen at IBM - speed increase by inlining. */
#define smb_buf(buf) (((char *)(buf)) + smb_size + CVAL(buf,smb_wct)*2)
#define smb_buf_const(buf) (((const char *)(buf)) + smb_size + CVAL(buf,smb_wct)*2)
#define smb_buflen(buf) (SVAL(buf,smb_vwv0 + (int)CVAL(buf, smb_wct)*2))

/* the remaining number of bytes in smb buffer 'buf' from pointer 'p'. */
#define smb_bufrem(buf, p) (smb_buflen(buf)-PTR_DIFF(p, smb_buf(buf)))
#define smbreq_bufrem(req, p) (req->buflen - PTR_DIFF(p, req->buf))


/* Note that chain_size must be available as an extern int to this macro. */
#define smb_offset(p,buf) (PTR_DIFF(p,buf+4))

#define smb_len(buf) smb_len_nbt(buf)
#define _smb_setlen(buf, len) _smb_setlen_nbt(buf, len)
#define smb_setlen(buf, len) smb_setlen_nbt(buf, len)

#define smb_len_large(buf) smb_len_tcp(buf)
#define _smb_setlen_large(buf, len) _smb_setlen_tcp(buf, len)

#define ENCRYPTION_REQUIRED(conn) ((conn) ? ((conn)->encrypt_level == SMB_SIGNING_REQUIRED) : false)
#define IS_CONN_ENCRYPTED(conn) ((conn) ? (conn)->encrypted_tid : false)

/****************************************************************************
 Return True if the offset is at zero.
****************************************************************************/

#define dptr_zero(buf) (IVAL(buf,1) == 0)

/*******************************************************************
copy an IP address from one buffer to another
********************************************************************/

#define putip(dest,src) memcpy(dest,src,4)

/*******************************************************************
 Return True if a server has CIFS UNIX capabilities.
********************************************************************/

#define SERVER_HAS_UNIX_CIFS(c) (smb1cli_conn_capabilities(c->conn) & CAP_UNIX)

/****************************************************************************
 Make a filename into unix format.
****************************************************************************/

#define IS_DIRECTORY_SEP(c) ((c) == '\\' || (c) == '/')
#define unix_format(fname) string_replace(fname,'\\','/')

/****************************************************************************
 Make a file into DOS format.
****************************************************************************/

#define dos_format(fname) string_replace(fname,'/','\\')

/*****************************************************************************
 Check to see if we are a DC for this domain
*****************************************************************************/

#define IS_DC  (lp_server_role()==ROLE_DOMAIN_PDC || lp_server_role()==ROLE_DOMAIN_BDC || lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC) 
#define IS_AD_DC  (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC)

/*
 * If you add any entries to KERBEROS_VERIFY defines, please modify the below expressions
 * so they remain accurate.
 */
#define USE_KERBEROS_KEYTAB (KERBEROS_VERIFY_SECRETS != lp_kerberos_method())
#define USE_SYSTEM_KEYTAB \
    ((KERBEROS_VERIFY_SECRETS_AND_KEYTAB == lp_kerberos_method()) || \
     (KERBEROS_VERIFY_SYSTEM_KEYTAB == lp_kerberos_method()))

/*****************************************************************************
 Safe allocation macros.
*****************************************************************************/

#define SMB_MALLOC_ARRAY(type,count) (type *)malloc_array(sizeof(type),(count))
#define SMB_MEMALIGN_ARRAY(type,align,count) (type *)memalign_array(sizeof(type),align,(count))
#define SMB_REALLOC(p,s) Realloc((p),(s),True)	/* Always frees p on error or s == 0 */
#define SMB_REALLOC_ARRAY(p,type,count) (type *)realloc_array((p),sizeof(type),(count),True) /* Always frees p on error or s == 0 */
#define SMB_CALLOC_ARRAY(type,count) (type *)calloc_array(sizeof(type),(count))
#define SMB_XMALLOC_P(type) (type *)smb_xmalloc_array(sizeof(type),1)
#define SMB_XMALLOC_ARRAY(type,count) (type *)smb_xmalloc_array(sizeof(type),(count))

#define TALLOC(ctx, size) talloc_named_const(ctx, size, __location__)
#define TALLOC_ZERO(ctx, size) _talloc_zero(ctx, size, __location__)
#define TALLOC_SIZE(ctx, size) talloc_named_const(ctx, size, __location__)
#define TALLOC_ZERO_SIZE(ctx, size) _talloc_zero(ctx, size, __location__)

#define TALLOC_REALLOC(ctx, ptr, count) _talloc_realloc(ctx, ptr, count, __location__)
#define talloc_destroy(ctx) talloc_free(ctx)
#ifndef TALLOC_FREE
#define TALLOC_FREE(ctx) do { talloc_free(ctx); ctx=NULL; } while(0)
#endif

/* only define PARANOID_MALLOC_CHECKER with --enable-developer */

#if defined(DEVELOPER)
#  define PARANOID_MALLOC_CHECKER 1
#endif

#if defined(PARANOID_MALLOC_CHECKER)

/* Get medieval on our ass about malloc.... */

/* Restrictions on malloc/realloc/calloc. */
#ifdef malloc
#undef malloc
#endif
#define malloc(s) __ERROR_DONT_USE_MALLOC_DIRECTLY

#ifdef realloc
#undef realloc
#endif
#define realloc(p,s) __ERROR_DONT_USE_REALLOC_DIRECTLY

#ifdef calloc
#undef calloc
#endif
#define calloc(n,s) __ERROR_DONT_USE_CALLOC_DIRECTLY

#ifdef strndup
#undef strndup
#endif
#define strndup(s,n) __ERROR_DONT_USE_STRNDUP_DIRECTLY

#ifdef strdup
#undef strdup
#endif
#define strdup(s) __ERROR_DONT_USE_STRDUP_DIRECTLY

#define SMB_MALLOC(s) malloc_(s)
#define SMB_MALLOC_P(type) (type *)malloc_(sizeof(type))

#define SMB_STRDUP(s) smb_xstrdup(s)
#define SMB_STRNDUP(s,n) smb_xstrndup(s,n)

#else

/* Regular malloc code. */

#define SMB_MALLOC(s) malloc(s)
#define SMB_MALLOC_P(type) (type *)malloc(sizeof(type))

#define SMB_STRDUP(s) strdup(s)
#define SMB_STRNDUP(s,n) strndup(s,n)

#endif

#define ADD_TO_ARRAY(mem_ctx, type, elem, array, num) \
do { \
	*(array) = ((mem_ctx) != NULL) ? \
		talloc_realloc(mem_ctx, (*(array)), type, (*(num))+1) : \
		SMB_REALLOC_ARRAY((*(array)), type, (*(num))+1); \
	SMB_ASSERT((*(array)) != NULL); \
	(*(array))[*(num)] = (elem); \
	(*(num)) += 1; \
} while (0)

#define ADD_TO_LARGE_ARRAY(mem_ctx, type, elem, array, num, size) \
	add_to_large_array((mem_ctx), sizeof(type), &(elem), (void *)(array), (num), (size));

#define trans_oob(bufsize, offset, length) \
	smb_buffer_oob(bufsize, offset, length)

#endif /* _SMB_MACROS_H */
