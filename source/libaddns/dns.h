/*
  Linux DNS client library implementation

  Copyright (C) 2006 Krishna Ganugapati <krishnag@centeris.com>
  Copyright (C) 2006 Gerald Carter <jerry@samba.org>

     ** NOTE! The following LGPL license applies to the libaddns
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  
  02110-1301  USA
*/

#ifndef _DNS_H
#define _DNS_H

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>

#ifdef HAVE_UUID_UUID_H
#include <uuid/uuid.h>
#endif

#ifdef HAVE_KRB5_H
#include <krb5.h>
#endif

#if HAVE_GSSAPI_H
#include <gssapi.h>
#elif HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#elif HAVE_GSSAPI_GSSAPI_GENERIC_H
#include <gssapi/gssapi_generic.h>
#endif

#if defined(HAVE_GSSAPI_H) || defined(HAVE_GSSAPI_GSSAPI_H) || defined(HAVE_GSSAPI_GSSAPI_GENERIC_H)
#define HAVE_GSSAPI_SUPPORT    1
#endif

#include <talloc.h>

#define TALLOC(ctx, size) talloc_named_const(ctx, size, __location__)
#define TALLOC_P(ctx, type) (type *)talloc_named_const(ctx, sizeof(type), #type)
#define TALLOC_ARRAY(ctx, type, count) (type *)_talloc_array(ctx, sizeof(type), count, #type)
#define TALLOC_MEMDUP(ctx, ptr, size) _talloc_memdup(ctx, ptr, size, __location__)
#define TALLOC_ZERO(ctx, size) _talloc_zero(ctx, size, __location__)
#define TALLOC_ZERO_P(ctx, type) (type *)_talloc_zero(ctx, sizeof(type), #type)
#define TALLOC_ZERO_ARRAY(ctx, type, count) (type *)_talloc_zero_array(ctx, sizeof(type), count, #type)
#define TALLOC_REALLOC(ctx, ptr, count) _talloc_realloc(ctx, ptr, count, __location__)
#define TALLOC_REALLOC_ARRAY(ctx, ptr, type, count) (type *)_talloc_realloc_array(ctx, ptr, sizeof(type), count, #type)
#define TALLOC_FREE(ctx) do { if ((ctx) != NULL) {talloc_free(ctx); ctx=NULL;} } while(0)

/*******************************************************************
   Type definitions for int16, int32, uint16 and uint32.  Needed
   for Samba coding style
*******************************************************************/

#ifndef uint8
#  define uint8 unsigned char
#endif

#if !defined(int16) && !defined(HAVE_INT16_FROM_RPC_RPC_H)
#  if (SIZEOF_SHORT == 4)
#    define int16 __ERROR___CANNOT_DETERMINE_TYPE_FOR_INT16;
#  else /* SIZEOF_SHORT != 4 */
#    define int16 short
#  endif /* SIZEOF_SHORT != 4 */
   /* needed to work around compile issue on HP-UX 11.x */
#  define _INT16        1
#endif

/*
 * Note we duplicate the size tests in the unsigned
 * case as int16 may be a typedef from rpc/rpc.h
 */

#if !defined(uint16) && !defined(HAVE_UINT16_FROM_RPC_RPC_H)
#  if (SIZEOF_SHORT == 4)
#    define uint16 __ERROR___CANNOT_DETERMINE_TYPE_FOR_INT16;
#  else /* SIZEOF_SHORT != 4 */
#    define uint16 unsigned short
#  endif /* SIZEOF_SHORT != 4 */
#endif

#if !defined(int32) && !defined(HAVE_INT32_FROM_RPC_RPC_H)
#  if (SIZEOF_INT == 4)
#    define int32 int
#  elif (SIZEOF_LONG == 4)
#    define int32 long
#  elif (SIZEOF_SHORT == 4)
#    define int32 short
#  else
     /* uggh - no 32 bit type?? probably a CRAY. just hope this works ... */
#    define int32 int
#  endif
   /* needed to work around compile issue on HP-UX 11.x */
#  define _INT32        1
#endif

/*
 * Note we duplicate the size tests in the unsigned
 * case as int32 may be a typedef from rpc/rpc.h
 */

#if !defined(uint32) && !defined(HAVE_UINT32_FROM_RPC_RPC_H)
#  if (SIZEOF_INT == 4)
#    define uint32 unsigned int
#  elif (SIZEOF_LONG == 4)
#    define uint32 unsigned long
#  elif (SIZEOF_SHORT == 4)
#    define uint32 unsigned short
#  else
      /* uggh - no 32 bit type?? probably a CRAY. just hope this works ... */
#    define uint32 unsigned
#  endif
#endif

/*
 * check for 8 byte long long
 */

#if !defined(uint64)
#  if (SIZEOF_LONG == 8)
#    define uint64 unsigned long
#  elif (SIZEOF_LONG_LONG == 8)
#    define uint64 unsigned long long
#  endif /* don't lie.  If we don't have it, then don't use it */
#endif

/* needed on Sun boxes */
#ifndef INADDR_NONE
#define INADDR_NONE          0xFFFFFFFF
#endif

#include "dnserr.h"


#define DNS_TCP			1
#define DNS_UDP			2

#define DNS_OPCODE_UPDATE	1

#define BAIL_ON_ERROR(x) \
	if ((x)){ \
		goto error; \
	}

#define BAIL_ON_DNS_ERROR(x) \
	if ( !ERR_DNS_IS_OK((x)) ) { \
		goto error; \
	}

#define BAIL_ON_SEC_ERROR(dwMajorStatus) \
	if ((dwMajorStatus!= GSS_S_COMPLETE)\
			&& (dwMajorStatus != GSS_S_CONTINUE_NEEDED)) {\
		goto sec_error; \
	}

/* DNS Class Types */

#define DNS_CLASS_IN		1
#define DNS_CLASS_ANY		255
#define DNS_CLASS_NONE		254

/* DNS RR Types */

#define DNS_RR_A		1

#define DNS_TCP_PORT		53
#define DNS_UDP_PORT		53

#define QTYPE_A         1
#define QTYPE_NS        2
#define QTYPE_MD        3
#define QTYPE_CNAME	5
#define QTYPE_SOA	6
#define QTYPE_ANY	255
#define	QTYPE_TKEY	249
#define QTYPE_TSIG	250

/*
MF              4 a mail forwarder (Obsolete - use MX)
CNAME           5 the canonical name for an alias
SOA             6 marks the start of a zone of authority
MB              7 a mailbox domain name (EXPERIMENTAL)
MG              8 a mail group member (EXPERIMENTAL)
MR              9 a mail rename domain name (EXPERIMENTAL)
NULL            10 a null RR (EXPERIMENTAL)
WKS             11 a well known service description
PTR             12 a domain name pointer
HINFO           13 host information
MINFO           14 mailbox or mail list information
MX              15 mail exchange
TXT             16 text strings
*/

#define QR_QUERY	 0x0000
#define QR_RESPONSE	 0x0001

#define OPCODE_QUERY 0x00
#define OPCODE_IQUERY	0x01
#define OPCODE_STATUS	0x02

#define AA			1

#define RECURSION_DESIRED	0x01

#define RCODE_NOERROR          0
#define RCODE_FORMATERROR      1
#define RCODE_SERVER_FAILURE   2
#define RCODE_NAME_ERROR       3
#define RCODE_NOTIMPLEMENTED   4
#define RCODE_REFUSED          5

#define SENDBUFFER_SIZE		65536
#define RECVBUFFER_SIZE		65536

#define DNS_ONE_DAY_IN_SECS	86400
#define DNS_TEN_HOURS_IN_SECS	36000

#define SOCKET_ERROR 		-1
#define INVALID_SOCKET		-1

#define  DNS_NO_ERROR		0
#define  DNS_FORMAT_ERROR	1
#define  DNS_SERVER_FAILURE	2
#define  DNS_NAME_ERROR		3
#define  DNS_NOT_IMPLEMENTED	4
#define  DNS_REFUSED		5

typedef long HANDLE;

#ifndef _BOOL
typedef int BOOL;

#define _BOOL			/* So we don't typedef BOOL again */
#endif


typedef struct dns_domain_label {
	struct dns_domain_label *pNext;
	char *pszLabel;
	int32 dwLength;
} DNS_DOMAIN_LABEL;

typedef struct {
	DNS_DOMAIN_LABEL *pLabelList;
} DNS_DOMAIN_NAME;

typedef struct {
	DNS_DOMAIN_NAME *pDomainName;
	int16 wQueryType;
	int16 wQueryClass;
} DNS_QUESTION_RECORD;


typedef struct {
	DNS_DOMAIN_NAME *pDomainName;
	int16 wZoneType;
	int16 wZoneClass;
} DNS_ZONE_RECORD;


typedef struct {
	DNS_DOMAIN_NAME *pDomainName;
	int16 wType;
	int16 wClass;
	int32 dwTTL;
	int16 wRDataSize;
	uint8 *pRData;
} DNS_RR_HEADER;


typedef struct {
	uint8 *pDefData;
} DNS_DEF_RDATA;

typedef struct {
	int16 wAlgorithmOffset;
	int16 wInceptionOffset;
	int16 wExpirationOffset;
	int16 wModeOffset;
	int16 wErrorOffset;
	int16 wKeySizeOffset;
	int16 wKeyDataOffset;
	int16 wOtherSizeOffset;
	int16 wOtherDataOffset;
} DNS_TKEY_OFFSETS;

typedef struct {
	int16 wAlgorithmOffset;
	int16 wTimeSignedOffset;
	int16 wFudgeOffset;
	int16 wMacSizeOffset;
	int16 wMacDataOffset;
	int16 wOriginalMessageIdOffset;
	int16 wErrorOffset;
	int16 wOtherSizeOffset;
	int16 wOtherDataOffset;
} DNS_TSIG_OFFSETS;


typedef struct {
	DNS_RR_HEADER RRHeader;
	union {
		DNS_TKEY_OFFSETS TKey;
		DNS_TSIG_OFFSETS TSig;
	} Offsets;
	uint8 *pRData;
} DNS_RR_RECORD;


typedef struct {
	int16 wIdentification;
	int16 wParameter;
	int16 wQuestions;
	int16 wAnswers;
	int16 wAuthoritys;
	int16 wAdditionals;
	DNS_QUESTION_RECORD **ppQuestionRRSet;
	DNS_RR_RECORD **ppAnswerRRSet;
	DNS_RR_RECORD **ppAuthorityRRSet;
	DNS_RR_RECORD **ppAdditionalRRSet;
} DNS_REQUEST;


typedef struct {
	int16 wIdentification;
	int16 wParameter;
	int16 wZones;
	int16 wPRs;
	int16 wUpdates;
	int16 wAdditionals;
	DNS_ZONE_RECORD **ppZoneRRSet;
	DNS_RR_RECORD **ppPRRRSet;
	DNS_RR_RECORD **ppUpdateRRSet;
	DNS_RR_RECORD **ppAdditionalRRSet;
} DNS_UPDATE_REQUEST;


typedef struct {
	int16 wIdentification;
	int16 wParameter;
	int16 wQuestions;
	int16 wAnswers;
	int16 wAuthoritys;
	int16 wAdditionals;
	DNS_QUESTION_RECORD **ppQuestionRRSet;
	DNS_RR_RECORD **ppAnswerRRSet;
	DNS_RR_RECORD **ppAuthorityRRSet;
	DNS_RR_RECORD **ppAdditionalRRSet;
	uint8 *pDNSOutBuffer;
	int32 dwNumBytes;
} DNS_RESPONSE;

typedef struct {
	int16 wIdentification;
	int16 wParameter;
	int16 wZones;
	int16 wPRs;
	int16 wUpdates;
	int16 wAdditionals;
	DNS_ZONE_RECORD **ppZoneRRSet;
	DNS_RR_RECORD **ppPRRRSet;
	DNS_RR_RECORD **ppUpdateRRSet;
	DNS_RR_RECORD **ppAdditionalRRSet;
	uint8 *pDNSOutBuffer;
	int32 dwNumBytes;
} DNS_UPDATE_RESPONSE;

typedef struct {
	int32 hType;
	int s;
	struct sockaddr RecvAddr;
} DNS_CONNECTION_CONTEXT;

typedef struct {
	uint8 *pSendBuffer;
	int32 dwBufferSize;
	int32 dwBytesWritten;
	int32 dwBufferOffset;
} DNS_SENDBUFFER_CONTEXT;

typedef struct {
	uint8 *pRecvBuffer;
	int32 dwBufferSize;
	int32 dwBytesRecvd;
	int32 dwBytesRead;
} DNS_RECEIVEBUFFER_CONTEXT;

/* from dnsutils.c */

int32 DNSGenerateIdentifier( int16 * pwIdentifer ); 
int32 DNSGetDomainNameLength( DNS_DOMAIN_NAME * pDomainName, int32 * pdwLength ); 
int32 DNSCopyDomainName( uint8 * pBuffer, DNS_DOMAIN_NAME * pDomainName, int32 * pdwCopied ); 
int32 DNSAllocateString( char *pszInputString, char **ppszOutputString );
int32 DNSGenerateKeyName( char **pszKeyName ); 
int32 DNSMakeRRHeader( DNS_RR_HEADER * pDNSRR, char *szOwnerName, int16 wType, int32 dwTTL ); 
int32 DNSDomainNameFromString( char *pszDomainName, DNS_DOMAIN_NAME ** ppDomainName ); 
int32 DNSAppendLabel( DNS_DOMAIN_LABEL * pLabelList, DNS_DOMAIN_LABEL * pLabel, DNS_DOMAIN_LABEL ** ppNewLabelList ); 
int32 DNSGenerateKeyName( char **ppszKeyName ); 
void DNSRecordGenerateOffsets( DNS_RR_RECORD * pDNSRecord );
int32 MapDNSResponseCodes( int16 wResponseCode ); 
int32 GetLastError( void );
int32 WSAGetLastError( void );
int32 DNSAllocateMemory(int32 dwSize, void * * ppMemory);
int32 DNSReallocMemory(void *  pMemory, void * * ppNewMemory, int32 dwSize);
void DNSFreeMemory( void * pMemory );
int32 DNSAllocateString(char *pszInputString, char **ppszOutputString);
void DNSFreeString(char * pszString);
void DNSFreeDomainName(DNS_DOMAIN_NAME *pDomainName);

/* from dnsrecord.c */

int32 DNSCreateDeleteRecord( char *szHost, int16 wClass, int16 wType, DNS_RR_RECORD ** ppDNSRecord ); 
int32 DNSCreateARecord( char *szHost, int16 wClass, int16 wType, int32 dwIP, DNS_RR_RECORD ** ppDNSRecord ); 
int32 DNSCreateTKeyRecord( char *szKeyName, uint8 * pKeyData, int16 dwKeyLen, DNS_RR_RECORD ** ppDNSRecord ); 
int32 DNSCreateTSIGRecord( char *szKeyName, int32 dwTimeSigned, int16 wFudge, int16 wOriginalID, uint8 * pMac, int16 wMacSize, DNS_RR_RECORD ** ppDNSRecord ); 
int32 DNSCreateQuestionRecord( char *pszQName, int16 wQType, int16 wQClass, DNS_QUESTION_RECORD ** ppDNSQuestionRecord ); 
int32 DNSAddQuestionSection( DNS_REQUEST * pDNSRequest, DNS_QUESTION_RECORD * pDNSQuestion ); 
int32 DNSAddAdditionalSection( DNS_REQUEST * pDNSRequest, DNS_RR_RECORD * pDNSRecord );
int32 DNSAddAnswerSection( DNS_REQUEST * pDNSRequest, DNS_RR_RECORD * pDNSRecord );
int32 DNSAddAuthoritySection( DNS_REQUEST * pDNSRequest, DNS_RR_RECORD * pDNSRecord );
int32 DNSCreateZoneRecord( char *pszZName, DNS_ZONE_RECORD ** ppDNSZoneRecord );
int32 DNSFreeZoneRecord( DNS_ZONE_RECORD * pDNSZoneRecord );
int32 DNSCreateNameInUseRecord( char *pszName, int32 qtype, struct in_addr *addr, DNS_RR_RECORD ** ppDNSRRRecord );
int32 DNSCreateNameNotInUseRecord( char *pszName, int32 qtype, DNS_RR_RECORD ** ppDNSRRRecord );

/* from dnsresponse.c */

int32 DNSStdReceiveStdResponse( HANDLE hDNSHandle, DNS_RESPONSE ** ppDNSResponse ); 
int32 DNSUnmarshallDomainName( HANDLE hRecvBuffer, DNS_DOMAIN_NAME ** ppDomainName ); 
int32 DNSUnmarshallRRHeader( HANDLE hRecvBuffer, DNS_RR_HEADER * pRRHeader ); 
int32 DNSUnmarshallRData( HANDLE hRecvBuffer, int32 dwSize, uint8 ** ppRData, int32 * pdwRead ); 
int32 DNSUpdateGetResponseCode( DNS_UPDATE_RESPONSE * pDNSUpdateResponse, int32 * pdwResponseCode );

/* from dnsrequest.c */

int32 DNSStdSendMarshallSection( HANDLE hSendBuffer, DNS_RR_RECORD ** ppDNSAnswerRRRecords, int16 wAnswers ); 
int32 DNSMarshallDomainName( HANDLE hSendBuffer, DNS_DOMAIN_NAME * pDomainName ); 
int32 DNSMarshallRRHeader( HANDLE hSendBuffer, DNS_RR_RECORD * pDNSRecord ); 
int32 DNSMarshallRData( HANDLE hSendBuffer, DNS_RR_RECORD * pDNSRecord ); 
int32 DNSWriteDomainName( HANDLE hDNSHandle, DNS_DOMAIN_NAME * pDomainName );
void DNSFreeRequest( DNS_REQUEST * pDNSRequest );
int32 DNSStdAddQuestionSection( DNS_REQUEST * pDNSRequest, DNS_QUESTION_RECORD * pDNSQuestion ); 
int32 DNSStdAddAdditionalSection( DNS_REQUEST * pDNSRequest, DNS_RR_RECORD * pDNSRecord ); 
int32 DNSStdCreateStdRequest( DNS_REQUEST ** ppDNSRequest );
int32 DNSStdSendStdRequest2( HANDLE hDNSServer, DNS_REQUEST * pDNSRequest );

/* from dnsuprequest.c */

int32 DNSUpdateSendUpdateRequest2( HANDLE hSendBuffer, DNS_UPDATE_REQUEST * pDNSRequest );
int32 DNSUpdateBuildRequestMessage( DNS_UPDATE_REQUEST * pDNSRequest, HANDLE * phSendBuffer );
void DNSUpdateFreeRequest( DNS_UPDATE_REQUEST * pDNSRequest ); 
int32 DNSWriteDomainName( HANDLE hDNSHandle, DNS_DOMAIN_NAME * pDomainName ); 
void DNSUpdateFreeRequest( DNS_UPDATE_REQUEST * pDNSRequest ); 
int32 DNSUpdateAddZoneSection( DNS_UPDATE_REQUEST * pDNSRequest, DNS_ZONE_RECORD * pDNSZone ); 
int32 DNSUpdateAddAdditionalSection( DNS_UPDATE_REQUEST * pDNSRequest, DNS_RR_RECORD * pDNSRecord ); 
int32 DNSUpdateAddPRSection( DNS_UPDATE_REQUEST * pDNSRequest, DNS_RR_RECORD * pDNSRecord ); 
int32 DNSUpdateAddUpdateSection( DNS_UPDATE_REQUEST * pDNSRequest, DNS_RR_RECORD * pDNSRecord ); 
int32 DNSUpdateCreateUpdateRequest( DNS_UPDATE_REQUEST ** ppDNSRequest );

/* from dnssock.c */

DNS_ERROR DNSOpen( char *nameserver, int32 dwType, HANDLE * phDNSServer );
int32 DNSReceiveBufferContext( HANDLE hDNSHandle, HANDLE hDNSRecvBuffer, int32 * pdwBytesRead );
int32 DNSCreateSendBuffer( HANDLE * phDNSSendBuffer );
int32 DNSMarshallBuffer( HANDLE hDNSSendBuffer, uint8 * pDNSSendBuffer, int32 dwBufferSize, int32 * pdwBytesWritten );;
int32 DNSSendBufferContext( HANDLE hDNSServer, HANDLE hSendBuffer, int32 * pdwBytesSent );
int32 DNSCreateReceiveBuffer( HANDLE * phDNSRecvBuffer );
int32 DNSUnmarshallBuffer( HANDLE hDNSRecvBuffer, uint8 * pDNSRecvBuffer, int32 dwBufferSize, int32 * pdwBytesRead );
int32 DNSUnmarshallDomainNameAtOffset( HANDLE hRecvBuffer, int16 wOffset, DNS_DOMAIN_NAME ** ppDomainName );
int32 DNSReceiveBufferMoveBackIndex( HANDLE hRecvBuffer, int16 wOffset );
void DNSFreeSendBufferContext( HANDLE hSendBuffer );
int32 DNSGetSendBufferContextSize( HANDLE hSendBuffer );
uint8 *DNSGetSendBufferContextBuffer( HANDLE hSendBuffer );


/* from dnsgss.c */

#ifdef HAVE_GSSAPI_SUPPORT

int32 DNSVerifyResponseMessage_GSSSuccess( gss_ctx_id_t * pGSSContext, DNS_RR_RECORD * pClientTKeyRecord, DNS_RESPONSE * pDNSResponse ); 
int32 DNSVerifyResponseMessage_GSSContinue( gss_ctx_id_t * pGSSContext, DNS_RR_RECORD * pClientTKeyRecord, DNS_RESPONSE * pDNSResponse, uint8 ** ppServerKeyData, int16 * pwServerKeyDataSize );
int32 DNSResponseGetRCode( DNS_RESPONSE * pDNSResponse, int16 * pwRCode );
int32 DNSResponseGetTSIGRecord( DNS_RESPONSE * pDNSResponse, DNS_RR_RECORD ** ppTSIGRecord ); 
int32 DNSCompareTKeyRecord( DNS_RR_RECORD * pClientTKeyRecord, DNS_RR_RECORD * pTKeyRecord );
int32 DNSBuildTKeyQueryRequest( char *szKeyName, uint8 * pKeyData, int32 dwKeyLen, DNS_REQUEST ** ppDNSRequest ); 
int32 DNSResponseGetTKeyRecord( DNS_RESPONSE * pDNSResponse, DNS_RR_RECORD ** ppTKeyRecord ); 
int32 DNSGetTKeyData( DNS_RR_RECORD * pTKeyRecord, uint8 ** ppKeyData, int16 * pwKeyDataSize ); 
int32 DNSNegotiateSecureContext( HANDLE hDNSServer, char *szDomain, char *szServerName, char *szKeyName, gss_ctx_id_t * pGSSContext ); 
void display_status( const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat ); 
int32 DNSNegotiateContextAndSecureUpdate( HANDLE hDNSServer, char *szServiceName, char *szDomainName, char *szHost, int32 dwIPAddress );

#endif	/* HAVE_GSSAPI_SUPPORT */

/* from dnsupdate.c */

int32 DNSSendUpdate( HANDLE hDNSServer, char *szDomainName, char *szHost, struct in_addr *iplist, int num_addrs, DNS_UPDATE_RESPONSE ** ppDNSUpdateResponse );
int32 DNSBuildSignatureBuffer( int32 dwMaxSignatureSize, uint8 ** ppSignature ); 
int32 DNSBuildMessageBuffer( DNS_UPDATE_REQUEST * pDNSUpdateRequest, char *szKeyName, int32 * pdwTimeSigned, int16 * pwFudge, uint8 ** ppMessageBuffer, int32 * pdwMessageSize ); 
int32 DNSClose( HANDLE hDNSUpdate );

#ifdef HAVE_GSSAPI_SUPPORT
int32 DNSSendSecureUpdate( HANDLE hDNSServer, gss_ctx_id_t * pGSSContext, char *pszKeyName, char *szDomainName, char *szHost, int32 dwIP, DNS_UPDATE_RESPONSE ** ppDNSUpdateResponse );
int32 DNSUpdateGenerateSignature( gss_ctx_id_t * pGSSContext, DNS_UPDATE_REQUEST * pDNSUpdateRequest, char *pszKeyName ); 
#endif  /* HAVE_GSSAPI_SUPPORT */

/* from dnsupresp.c */

int32 DNSUpdateReceiveUpdateResponse( HANDLE hDNSHandle, DNS_UPDATE_RESPONSE ** ppDNSResponse );

/* from dnssign.c */

#ifdef HAVE_GSSAPI_SUPPORT
int32 DNSGenerateHash( gss_ctx_id_t * gss_context, uint8 * pRequestBuffer, uint8 ** ppMAC, int32 * pdwMacLen );
int32 BuildHashInputBuffer( DNS_REQUEST * pDNSRequest, int32 dwLength, uint8 ** ppHashInputBuffer, int32 * pdwHashInputBufferLen );
int32 DNSStdValidateAndGetTSIGRecord( gss_ctx_id_t * gss_context, DNS_RESPONSE * pDNSResponse, DNS_RR_RECORD ** ppDNSTSIGRecord );
#endif  /* HAVE_GSSAPI_SUPPORT */


#endif	/* _DNS_H */
