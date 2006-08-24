/*
  Public Interface file for Linux DNS client library implementation

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

#include "dns.h"
#include <ctype.h>


#ifdef HAVE_GSSAPI_SUPPORT

/*********************************************************************
*********************************************************************/

static int strupr( char *szDomainName )
{
	if ( !szDomainName ) {
		return ( 0 );
	}
	while ( *szDomainName != '\0' ) {
		*szDomainName = toupper( *szDomainName );
		szDomainName++;
	}
	return ( 0 );
}

/*********************************************************************
*********************************************************************/

int32 DNSBuildTKeyQueryRequest( char *szKeyName,
			  uint8 * pKeyData,
			  int32 dwKeyLen, DNS_REQUEST ** ppDNSRequest )
{
	int32 dwError = 0;
	DNS_RR_RECORD *pDNSTKeyRecord = NULL;
	DNS_REQUEST *pDNSRequest = NULL;
	DNS_QUESTION_RECORD *pDNSQuestionRecord = NULL;

	dwError = DNSStdCreateStdRequest( &pDNSRequest );
	BAIL_ON_ERROR( dwError );

	dwError = DNSCreateQuestionRecord( szKeyName,
					   QTYPE_TKEY,
					   DNS_CLASS_IN,
					   &pDNSQuestionRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSStdAddQuestionSection( pDNSRequest, pDNSQuestionRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSCreateTKeyRecord( szKeyName,
				       pKeyData,
				       ( int16 ) dwKeyLen, &pDNSTKeyRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSStdAddAdditionalSection( pDNSRequest, pDNSTKeyRecord );
	BAIL_ON_ERROR( dwError );

	*ppDNSRequest = pDNSRequest;

	return dwError;

      error:

	*ppDNSRequest = NULL;

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSVerifyResponseMessage_GSSSuccess( gss_ctx_id_t * pGSSContext,
				     DNS_RR_RECORD * pClientTKeyRecord,
				     DNS_RESPONSE * pDNSResponse )
{
	int32 dwError = 0;
	DNS_RR_RECORD *pTKeyRecord = NULL;
	DNS_RR_RECORD *pTSIGRecord = NULL;
	int16 wRCode = 0;

	dwError = DNSResponseGetRCode( pDNSResponse, &wRCode );
	BAIL_ON_ERROR( dwError );

	if ( wRCode != 0 ) {
		dwError = ERROR_BAD_RESPONSE;
		BAIL_ON_ERROR( dwError );

	}

	dwError = DNSResponseGetTKeyRecord( pDNSResponse, &pTKeyRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSCompareTKeyRecord( pClientTKeyRecord, pTKeyRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSResponseGetTSIGRecord( pDNSResponse, &pTSIGRecord );
	BAIL_ON_ERROR( dwError );

/*				
	dwMajorStatus = GSS_VerifyMIC(
						pDNSResponse->pDNSResponseBuffer,
						pDNSResponse->dwNumBytes,
						pDNSRRRecord->RData.TSIGRData.pMAC,
						pDNSRRRecord->RData.TSIGRData.wMaxSize
						)
	BAIL_ON_ERROR(dwMajorStatus);*/

      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSVerifyResponseMessage_GSSContinue( gss_ctx_id_t * pGSSContext,
				      DNS_RR_RECORD * pClientTKeyRecord,
				      DNS_RESPONSE * pDNSResponse,
				      uint8 ** ppServerKeyData,
				      int16 * pwServerKeyDataSize )
{
	int32 dwError = 0;
	DNS_RR_RECORD *pTKeyRecord = NULL;
	int16 wRCode = 0;
	uint8 *pServerKeyData = NULL;
	int16 wServerKeyDataSize = 0;


	dwError = DNSResponseGetRCode( pDNSResponse, &wRCode );
	BAIL_ON_ERROR( dwError );
	if ( wRCode != 0 ) {
		dwError = ERROR_BAD_RESPONSE;
		BAIL_ON_ERROR( dwError );

	}

	dwError = DNSResponseGetTKeyRecord( pDNSResponse, &pTKeyRecord );
	BAIL_ON_ERROR( dwError );


	dwError = DNSCompareTKeyRecord( pClientTKeyRecord, pTKeyRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSGetTKeyData( pTKeyRecord,
				  &pServerKeyData, &wServerKeyDataSize );
	BAIL_ON_ERROR( dwError );

	*ppServerKeyData = pServerKeyData;
	*pwServerKeyDataSize = wServerKeyDataSize;

	return dwError;

      error:

	*ppServerKeyData = NULL;
	*pwServerKeyDataSize = 0;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSResponseGetRCode( DNS_RESPONSE * pDNSResponse, int16 * pwRCode )
{
	int32 dwError = 0;
	int16 wnParameter = 0;
	uint8 uChar = 0;

	wnParameter = htons( pDNSResponse->wParameter );

	/* Byte 0 is the most significate byte
	   Bit 12, 13, 14, 15 or Bit 4, 5, 6, 7 represent the RCode */

	memcpy( &uChar, ( uint8 * ) & wnParameter + 1, 1 );
	uChar >>= 4;
	*pwRCode = ( int16 ) uChar;

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSResponseGetTKeyRecord( DNS_RESPONSE * pDNSResponse,
			  DNS_RR_RECORD ** ppTKeyRecord )
{
	int32 dwError = 0;
	int16 wAnswers = 0;
	DNS_RR_RECORD *pDNSRecord = NULL;
	int32 i = 0;


	wAnswers = pDNSResponse->wAnswers;
	if ( !wAnswers ) {
		dwError = ERROR_INVALID_PARAMETER;
		BAIL_ON_ERROR( dwError );
	}

	for ( i = 0; i < wAnswers; i++ ) {
		pDNSRecord = *( pDNSResponse->ppAnswerRRSet + i );
		if ( pDNSRecord->RRHeader.wType == QTYPE_TKEY ) {
			*ppTKeyRecord = pDNSRecord;
			return dwError;
		}
	}
	dwError = ERROR_RECORD_NOT_FOUND;

      error:
	*ppTKeyRecord = NULL;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSResponseGetTSIGRecord( DNS_RESPONSE * pDNSResponse,
			  DNS_RR_RECORD ** ppTSIGRecord )
{
	int32 dwError = 0;
	int16 wAdditionals = 0;
	DNS_RR_RECORD *pDNSRecord = NULL;

	int32 i = 0;

	wAdditionals = pDNSResponse->wAdditionals;
	if ( !wAdditionals ) {
		dwError = ERROR_INVALID_PARAMETER;
		BAIL_ON_ERROR( dwError );
	}

	for ( i = 0; i < wAdditionals; i++ ) {
		pDNSRecord = *( pDNSResponse->ppAdditionalRRSet + i );
		if ( pDNSRecord->RRHeader.wType == QTYPE_TSIG ) {
			*ppTSIGRecord = pDNSRecord;
			return dwError;
		}
	}
	dwError = ERROR_RECORD_NOT_FOUND;

      error:
	*ppTSIGRecord = NULL;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSCompareTKeyRecord( DNS_RR_RECORD * pClientTKeyRecord,
		      DNS_RR_RECORD * pTKeyRecord )
{
	int32 dwError = 0;

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSNegotiateContextAndSecureUpdate( HANDLE hDNSServer,
				    char *szServiceName,
				    char *szDomainName,
				    char *szHost, int32 dwIPAddress )
{
	int32 dwError = 0;
	char *pszKeyName = NULL;
	gss_ctx_id_t ContextHandle = 0;
	gss_ctx_id_t *pContextHandle = &ContextHandle;

	dwError = DNSGenerateKeyName( &pszKeyName );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSNegotiateSecureContext( hDNSServer, szDomainName, szHost,
					   pszKeyName, pContextHandle );
	BAIL_ON_ERROR( dwError );

      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSGetTKeyData( DNS_RR_RECORD * pTKeyRecord,
		uint8 ** ppKeyData, int16 * pwKeyDataSize )
{
	int32 dwError = 0;
	int16 wKeyDataSize = 0;
	int16 wnKeyDataSize = 0;
	int32 dwKeyDataSizeOffset = 0;
	int32 dwKeyDataOffset = 0;
	uint8 *pKeyData = NULL;

	DNSRecordGenerateOffsets( pTKeyRecord );
	dwKeyDataSizeOffset = pTKeyRecord->Offsets.TKey.wKeySizeOffset;
	dwKeyDataOffset = pTKeyRecord->Offsets.TKey.wKeyDataOffset;
	memcpy( &wnKeyDataSize, pTKeyRecord->pRData + dwKeyDataSizeOffset,
		sizeof( int16 ) );
	wKeyDataSize = ntohs( wnKeyDataSize );

	dwError = DNSAllocateMemory( wKeyDataSize, ( void * ) &pKeyData );
	BAIL_ON_ERROR( dwError );

	memcpy( pKeyData, pTKeyRecord->pRData + dwKeyDataOffset,
		wKeyDataSize );

	*ppKeyData = pKeyData;
	*pwKeyDataSize = wKeyDataSize;

	return dwError;


      error:

	*ppKeyData = NULL;
	*pwKeyDataSize = 0;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSNegotiateSecureContext( HANDLE hDNSServer,
			   char *szDomain,
			   char *szServerName,
			   char *szKeyName, gss_ctx_id_t * pGSSContext )
{
	int32 dwError = 0;
	int32 dwMajorStatus = 0;
	char szUpperCaseDomain[256];
	char szTargetName[256];
	DNS_ERROR dns_status;

	gss_buffer_desc input_name;
	gss_buffer_desc input_desc, output_desc;
	DNS_REQUEST *pDNSRequest = NULL;
	DNS_RESPONSE *pDNSResponse = NULL;
	DNS_RR_RECORD *pClientTKeyRecord = NULL;
	HANDLE hDNSTcpServer = ( HANDLE ) NULL;

	uint8 *pServerKeyData = NULL;
	int16 wServerKeyDataSize = 0;

	OM_uint32 ret_flags = 0;

	int32 dwMinorStatus = 0;
	gss_name_t targ_name;
	gss_cred_id_t creds;

	krb5_principal host_principal;
	krb5_context ctx = NULL;

	gss_OID_desc nt_host_oid_desc =
		{ 10, ( char * ) ( ( void * ) "\052\206\110\206\367\022\001\002\002\002" ) };
	gss_OID_desc krb5_oid_desc =
		{ 9, ( char * ) ( ( void * ) "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02" ) };

	input_desc.value = NULL;
	input_desc.length = 0;

	dns_status = DNSOpen( szServerName, DNS_TCP, &hDNSTcpServer );
	BAIL_ON_DNS_ERROR( dns_status );


	memset( szUpperCaseDomain, 0, sizeof( szUpperCaseDomain ) );
	memcpy( szUpperCaseDomain, szDomain, strlen( szDomain ) );
	strupr( szUpperCaseDomain );

	dwMajorStatus = gss_acquire_cred( ( OM_uint32 * ) & dwMinorStatus,
					  GSS_C_NO_NAME,
					  GSS_C_INDEFINITE,
					  GSS_C_NO_OID_SET,
					  GSS_C_INITIATE,
					  &creds, NULL, NULL );
	BAIL_ON_SEC_ERROR( dwMajorStatus );
	printf( "After gss_acquire_cred %d\n", dwMajorStatus );

	sprintf( szTargetName, "dns/%s@%s", szServerName, szUpperCaseDomain );
	printf( "%s\n", szTargetName );

	krb5_init_context( &ctx );
	krb5_parse_name( ctx, szTargetName, &host_principal );
	krb5_free_context( ctx );

	input_name.value = &host_principal;
	input_name.length = sizeof( host_principal );

	dwMajorStatus = gss_import_name( ( OM_uint32 * ) & dwMinorStatus,
					 &input_name,
					 &nt_host_oid_desc, &targ_name );
	printf( "After gss_import_name %d\n", dwMajorStatus );
	BAIL_ON_SEC_ERROR( dwMajorStatus );
	printf( "After gss_import_name %d\n", dwMajorStatus );

	memset( pGSSContext, 0, sizeof( gss_ctx_id_t ) );
	*pGSSContext = GSS_C_NO_CONTEXT;

	do {

		dwMajorStatus = gss_init_sec_context( ( OM_uint32 * ) &
						      dwMinorStatus, creds,
						      pGSSContext, targ_name,
						      &krb5_oid_desc,
						      GSS_C_REPLAY_FLAG |
						      GSS_C_MUTUAL_FLAG |
						      GSS_C_SEQUENCE_FLAG |
						      GSS_C_CONF_FLAG |
						      GSS_C_INTEG_FLAG |
						      GSS_C_DELEG_FLAG, 0,
						      NULL, &input_desc, NULL,
						      &output_desc,
						      &ret_flags, NULL );
		display_status( "gss_init_context", dwMajorStatus,
				dwMinorStatus );
		BAIL_ON_SEC_ERROR( dwMajorStatus );
		printf( "After gss_init_sec_context %d\n", dwMajorStatus );

		switch ( dwMajorStatus ) {

		case GSS_S_COMPLETE:
			if ( output_desc.length != 0 ) {

				dwError = DNSBuildTKeyQueryRequest( szKeyName,
								    (uint8 *)output_desc.
								    value,
								    output_desc.
								    length,
								    &pDNSRequest );
				BAIL_ON_ERROR( dwError );

				dwError =
					DNSStdSendStdRequest2( hDNSTcpServer,
							       pDNSRequest );
				BAIL_ON_ERROR( dwError );


				dwError =
					DNSStdReceiveStdResponse
					( hDNSTcpServer, &pDNSResponse );
				BAIL_ON_ERROR( dwError );

				dwError =
					DNSVerifyResponseMessage_GSSSuccess
					( pGSSContext, pClientTKeyRecord,
					  pDNSResponse );
				BAIL_ON_ERROR( dwError );
			}
			break;


		case GSS_S_CONTINUE_NEEDED:
			if ( output_desc.length != 0 ) {

				dwError = DNSBuildTKeyQueryRequest( szKeyName,
								    (uint8 *)output_desc.
								    value,
								    output_desc.
								    length,
								    &pDNSRequest );
				BAIL_ON_ERROR( dwError );

				dwError =
					DNSStdSendStdRequest2( hDNSTcpServer,
							       pDNSRequest );
				BAIL_ON_ERROR( dwError );

				dwError =
					DNSStdReceiveStdResponse
					( hDNSTcpServer, &pDNSResponse );
				BAIL_ON_ERROR( dwError );

				dwError =
					DNSVerifyResponseMessage_GSSContinue
					( pGSSContext, pClientTKeyRecord,
					  pDNSResponse, &pServerKeyData,
					  &wServerKeyDataSize );
				BAIL_ON_ERROR( dwError );

				input_desc.value = pServerKeyData;
				input_desc.length = wServerKeyDataSize;
			}
			break;

		default:
			BAIL_ON_ERROR( dwError );
		}

	} while ( dwMajorStatus == GSS_S_CONTINUE_NEEDED );

	/* If we arrive here, we have a valid security context */

      sec_error:
      error:

	return dwError;

}

/*********************************************************************
*********************************************************************/

static void display_status_1( const char *m, OM_uint32 code, int type )
{
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc msg;
	OM_uint32 msg_ctx;

	msg_ctx = 0;
	while ( 1 ) {
		maj_stat = gss_display_status( &min_stat, code,
					       type, GSS_C_NULL_OID,
					       &msg_ctx, &msg );
		fprintf( stdout, "GSS-API error %s: %s\n", m,
			 ( char * ) msg.value );
		( void ) gss_release_buffer( &min_stat, &msg );

		if ( !msg_ctx )
			break;
	}
}

/*********************************************************************
*********************************************************************/

void display_status( const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat )
{
	display_status_1( msg, maj_stat, GSS_C_GSS_CODE );
	display_status_1( msg, min_stat, GSS_C_MECH_CODE );
}

#endif	/* HAVE_GSSAPI_SUPPORT */
