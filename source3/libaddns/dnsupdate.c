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

/********************************************************************
********************************************************************/

static int32 DNSSendUpdate1( HANDLE hDNSServer, char *szDomainName,
			     char *szHost, struct in_addr *iplist,
			     int num_ips,
			     DNS_UPDATE_RESPONSE * *ppDNSUpdateResponse )
{
	int32 dwError = 0;
	DNS_UPDATE_REQUEST *pDNSUpdateRequest = NULL;
	DNS_UPDATE_RESPONSE *pDNSUpdateResponse = NULL;
	DNS_ZONE_RECORD *pDNSZoneRecord = NULL;
	DNS_RR_RECORD *pDNSPRRecord = NULL;
	int i;

	dwError = DNSUpdateCreateUpdateRequest( &pDNSUpdateRequest );
	BAIL_ON_ERROR( dwError );

	dwError = DNSCreateZoneRecord( szDomainName, &pDNSZoneRecord );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSUpdateAddZoneSection( pDNSUpdateRequest, pDNSZoneRecord );
	BAIL_ON_ERROR( dwError );

	/* Add the CNAME not in user record */

	pDNSPRRecord = NULL;
	dwError =
		DNSCreateNameNotInUseRecord( szHost, QTYPE_CNAME,
					     &pDNSPRRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSUpdateAddPRSection( pDNSUpdateRequest, pDNSPRRecord );
	BAIL_ON_ERROR( dwError );

	/* Add a Prerequisite for each IP address to see if everything is already setup */

	for ( i = 0; i < num_ips; i++ ) {
		DNS_RR_RECORD *pDNSPrereq = NULL;

		dwError =
			DNSCreateNameInUseRecord( szHost, QTYPE_A, &iplist[i],
						  &pDNSPrereq );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSUpdateAddPRSection( pDNSUpdateRequest,
					       pDNSPrereq );
		BAIL_ON_ERROR( dwError );
	}

	dwError =
		DNSUpdateSendUpdateRequest2( hDNSServer, pDNSUpdateRequest );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSUpdateReceiveUpdateResponse( hDNSServer,
						&pDNSUpdateResponse );
	BAIL_ON_ERROR( dwError );

	*ppDNSUpdateResponse = pDNSUpdateResponse;

	return dwError;

      error:

	if ( pDNSZoneRecord ) {
		DNSFreeZoneRecord( pDNSZoneRecord );
	}

	if ( pDNSUpdateRequest ) {
		DNSUpdateFreeRequest( pDNSUpdateRequest );
	}

	*ppDNSUpdateResponse = NULL;
	return dwError;
}

/********************************************************************
********************************************************************/

static int32 DNSSendUpdate2( HANDLE hDNSServer, char *szDomainName,
			     char *szHost, struct in_addr *iplist,
			     int num_ips,
			     DNS_UPDATE_RESPONSE * *ppDNSUpdateResponse )
{
	int32 dwError = 0;
	DNS_UPDATE_REQUEST *pDNSUpdateRequest = NULL;
	DNS_UPDATE_RESPONSE *pDNSUpdateResponse = NULL;
	DNS_ZONE_RECORD *pDNSZoneRecord = NULL;
	DNS_RR_RECORD *pDNSPRRecord = NULL;
	int i;

	dwError = DNSUpdateCreateUpdateRequest( &pDNSUpdateRequest );
	BAIL_ON_ERROR( dwError );

	dwError = DNSCreateZoneRecord( szDomainName, &pDNSZoneRecord );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSUpdateAddZoneSection( pDNSUpdateRequest, pDNSZoneRecord );
	BAIL_ON_ERROR( dwError );

	/* Add the CNAME not in user record */

	pDNSPRRecord = NULL;
	dwError =
		DNSCreateNameNotInUseRecord( szHost, QTYPE_CNAME,
					     &pDNSPRRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSUpdateAddPRSection( pDNSUpdateRequest, pDNSPRRecord );
	BAIL_ON_ERROR( dwError );

	/* Add the IN not in user record */

	pDNSPRRecord = NULL;
	dwError =
		DNSCreateNameNotInUseRecord( szHost, QTYPE_A, &pDNSPRRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSUpdateAddPRSection( pDNSUpdateRequest, pDNSPRRecord );
	BAIL_ON_ERROR( dwError );


	for ( i = 0; i < num_ips; i++ ) {
		DNS_RR_RECORD *pDNSRRAddRecord = NULL;

		dwError =
			DNSCreateARecord( szHost, DNS_CLASS_IN, QTYPE_A,
					  ntohl( iplist[i].s_addr ),
					  &pDNSRRAddRecord );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSUpdateAddUpdateSection( pDNSUpdateRequest,
						   pDNSRRAddRecord );
		BAIL_ON_ERROR( dwError );
	}

	dwError =
		DNSUpdateSendUpdateRequest2( hDNSServer, pDNSUpdateRequest );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSUpdateReceiveUpdateResponse( hDNSServer,
						&pDNSUpdateResponse );
	BAIL_ON_ERROR( dwError );

	*ppDNSUpdateResponse = pDNSUpdateResponse;

	return dwError;

      error:

	if ( pDNSZoneRecord ) {
		DNSFreeZoneRecord( pDNSZoneRecord );
	}

	if ( pDNSUpdateRequest ) {
		DNSUpdateFreeRequest( pDNSUpdateRequest );
	}

	*ppDNSUpdateResponse = NULL;
	return dwError;
}

/********************************************************************
********************************************************************/

static int32 DNSSendUpdate3( HANDLE hDNSServer, char *szDomainName,
			     char *szHost, struct in_addr *iplist,
			     int num_ips,
			     DNS_UPDATE_RESPONSE * *ppDNSUpdateResponse )
{
	int32 dwError = 0;
	DNS_UPDATE_REQUEST *pDNSUpdateRequest = NULL;
	DNS_UPDATE_RESPONSE *pDNSUpdateResponse = NULL;
	DNS_ZONE_RECORD *pDNSZoneRecord = NULL;
	DNS_RR_RECORD *pDNSPRRecord = NULL;
	int i;
	DNS_RR_RECORD *pDNSRRAddRecord = NULL;

	dwError = DNSUpdateCreateUpdateRequest( &pDNSUpdateRequest );
	BAIL_ON_ERROR( dwError );

	dwError = DNSCreateZoneRecord( szDomainName, &pDNSZoneRecord );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSUpdateAddZoneSection( pDNSUpdateRequest, pDNSZoneRecord );
	BAIL_ON_ERROR( dwError );

	/* Add the CNAME not in user record */

	dwError =
		DNSCreateNameNotInUseRecord( szHost, QTYPE_CNAME,
					     &pDNSPRRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSUpdateAddPRSection( pDNSUpdateRequest, pDNSPRRecord );
	BAIL_ON_ERROR( dwError );

	/* Delete any existing A records */

	dwError =
		DNSCreateARecord( szHost, DNS_CLASS_ANY, QTYPE_A, 0,
				  &pDNSRRAddRecord );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSUpdateAddUpdateSection( pDNSUpdateRequest,
					   pDNSRRAddRecord );
	BAIL_ON_ERROR( dwError );


	for ( i = 0; i < num_ips; i++ ) {

		dwError =
			DNSCreateARecord( szHost, DNS_CLASS_IN, QTYPE_A,
					  ntohl( iplist[i].s_addr ),
					  &pDNSRRAddRecord );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSUpdateAddUpdateSection( pDNSUpdateRequest,
						   pDNSRRAddRecord );
		BAIL_ON_ERROR( dwError );
	}

	dwError =
		DNSUpdateSendUpdateRequest2( hDNSServer, pDNSUpdateRequest );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSUpdateReceiveUpdateResponse( hDNSServer,
						&pDNSUpdateResponse );
	BAIL_ON_ERROR( dwError );

	*ppDNSUpdateResponse = pDNSUpdateResponse;

	return dwError;

      error:

	if ( pDNSZoneRecord ) {
		DNSFreeZoneRecord( pDNSZoneRecord );
	}

	if ( pDNSUpdateRequest ) {
		DNSUpdateFreeRequest( pDNSUpdateRequest );
	}

	*ppDNSUpdateResponse = NULL;

	return dwError;
}

/********************************************************************
********************************************************************/

int32 DNSSendUpdate( HANDLE hDNSServer, char *szDomainName, char *szHost,
		     struct in_addr * iplist, int num_ips,
		     DNS_UPDATE_RESPONSE * *ppDNSUpdateResponse )
{
	int32 dwError = 0;
	int32 dwResponseCode = 0;
	DNS_UPDATE_RESPONSE *response = NULL;

	dwError = DNSSendUpdate1( hDNSServer, szDomainName, szHost,
				  iplist, num_ips, &response );
	BAIL_ON_ERROR( dwError );

	dwError = DNSUpdateGetResponseCode( response, &dwResponseCode );
	BAIL_ON_ERROR( dwError );

	if ( ( dwResponseCode == DNS_NO_ERROR )
	     || ( dwResponseCode == DNS_REFUSED ) ) {
		*ppDNSUpdateResponse = response;
		return dwError;
	}

	response = NULL;

	dwError = DNSSendUpdate2( hDNSServer, szDomainName, szHost,
				  iplist, num_ips, &response );
	BAIL_ON_ERROR( dwError );

	dwError = DNSUpdateGetResponseCode( response, &dwResponseCode );
	BAIL_ON_ERROR( dwError );

	if ( ( dwResponseCode == DNS_NO_ERROR )
	     || ( dwResponseCode == DNS_REFUSED ) ) {
		*ppDNSUpdateResponse = response;
		return dwError;
	}

	response = NULL;

	dwError = DNSSendUpdate3( hDNSServer, szDomainName, szHost,
				  iplist, num_ips, &response );

      error:
	*ppDNSUpdateResponse = response;

	return dwError;
}

/********************************************************************
********************************************************************/
#ifdef HAVE_GSSAPI_SUPPORT
int32 DNSSendSecureUpdate( HANDLE hDNSServer,
		     gss_ctx_id_t * pGSSContext,
		     char *pszKeyName,
		     char *szDomainName,
		     char *szHost,
		     int32 dwIP, DNS_UPDATE_RESPONSE ** ppDNSUpdateResponse )
{
	int32 dwError = 0;
	DNS_UPDATE_REQUEST *pDNSUpdateRequest = NULL;
	DNS_UPDATE_RESPONSE *pDNSUpdateResponse = NULL;
	DNS_ZONE_RECORD *pDNSZoneRecord = NULL;
	DNS_RR_RECORD *pDNSPRRecord = NULL;
	DNS_RR_RECORD *pDNSARecord = NULL;


	dwError = DNSUpdateCreateUpdateRequest( &pDNSUpdateRequest );
	BAIL_ON_ERROR( dwError );

	dwError = DNSCreateZoneRecord( szDomainName, &pDNSZoneRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSUpdateAddZoneSection( pDNSUpdateRequest,
					   pDNSZoneRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSCreateNameInUseRecord( szDomainName,
					    QTYPE_A, NULL, &pDNSPRRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSUpdateAddPRSection( pDNSUpdateRequest, pDNSPRRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSCreateDeleteRecord( szHost,
					 DNS_CLASS_ANY,
					 QTYPE_A, &pDNSARecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSUpdateAddUpdateSection( pDNSUpdateRequest, pDNSARecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSCreateARecord( szHost,
				    DNS_CLASS_IN,
				    QTYPE_A, dwIP, &pDNSARecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSUpdateAddUpdateSection( pDNSUpdateRequest, pDNSARecord );
	BAIL_ON_ERROR( dwError );

	/* Now Sign the Record */
	
	dwError = DNSUpdateGenerateSignature( pGSSContext,
					      pDNSUpdateRequest, pszKeyName );
	BAIL_ON_ERROR( dwError );


	dwError =
		DNSUpdateSendUpdateRequest2( hDNSServer, pDNSUpdateRequest );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSUpdateReceiveUpdateResponse( hDNSServer,
						&pDNSUpdateResponse );
	BAIL_ON_ERROR( dwError );

	*ppDNSUpdateResponse = pDNSUpdateResponse;

	return dwError;

      error:

	if ( pDNSZoneRecord ) {
		DNSFreeZoneRecord( pDNSZoneRecord );
	}

	if ( pDNSUpdateRequest ) {
		DNSUpdateFreeRequest( pDNSUpdateRequest );
	}

	*ppDNSUpdateResponse = NULL;

	return dwError;
}


/*********************************************************************
*********************************************************************/

int32 DNSUpdateGenerateSignature( gss_ctx_id_t * pGSSContext,
			    DNS_UPDATE_REQUEST * pDNSUpdateRequest,
			    char *pszKeyName )
{
	int32 dwError = 0;
	int32 dwMinorStatus = 0;
	HANDLE hSendBuffer = ( HANDLE ) NULL;
	uint8 *pMessageBuffer = NULL;
	int32 dwMessageSize = 0;
	int32 dwMaxSignatureSize = 0;
	uint8 *pSignature = NULL;
	int32 dwTimeSigned = 0;
	int16 wFudge = 0;
	gss_buffer_desc MsgDesc, MicDesc;
	DNS_RR_RECORD *pDNSTSIGRecord = NULL;

	dwError = DNSBuildMessageBuffer( pDNSUpdateRequest,
					 pszKeyName,
					 &dwTimeSigned,
					 &wFudge,
					 &pMessageBuffer, &dwMessageSize );
	BAIL_ON_ERROR( dwError );

	dwError = DNSBuildSignatureBuffer( dwMaxSignatureSize, &pSignature );
	BAIL_ON_ERROR( dwError );

	MsgDesc.value = pMessageBuffer;
	MsgDesc.length = dwMessageSize;

	MicDesc.value = NULL;
	MicDesc.length = 0;

	dwError = gss_get_mic( ( OM_uint32 * ) & dwMinorStatus,
			       *pGSSContext, 0, &MsgDesc, &MicDesc );
	display_status( "gss_init_context", dwError, dwMinorStatus );
	BAIL_ON_ERROR( dwError );

	dwError = DNSCreateTSIGRecord( pszKeyName,
				       dwTimeSigned,
				       wFudge,
				       pDNSUpdateRequest->wIdentification,
				       (uint8 *)MicDesc.value,
				       MicDesc.length, &pDNSTSIGRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSUpdateAddAdditionalSection( pDNSUpdateRequest,
						 pDNSTSIGRecord );
	BAIL_ON_ERROR( dwError );


      error:

	if ( hSendBuffer ) {
		DNSFreeSendBufferContext( hSendBuffer );
	}

	if ( pMessageBuffer ) {
		DNSFreeMemory( pMessageBuffer );
	}
	return dwError;

	if ( pSignature ) {
		DNSFreeMemory( pSignature );
	}

	return dwError;
}
#endif	/* HAVE_GSSAPI_SUPPORT */

/*********************************************************************
*********************************************************************/

int32 DNSBuildSignatureBuffer( int32 dwMaxSignatureSize, uint8 ** ppSignature )
{
	int32 dwError = 0;
	uint8 *pSignature = NULL;

	dwError = DNSAllocateMemory( dwMaxSignatureSize,
				     ( void * ) &pSignature );
	BAIL_ON_ERROR( dwError );

	*ppSignature = pSignature;

	return dwError;

      error:
	*ppSignature = NULL;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSBuildMessageBuffer( DNS_UPDATE_REQUEST * pDNSUpdateRequest,
		       char *szKeyName,
		       int32 * pdwTimeSigned,
		       int16 * pwFudge,
		       uint8 ** ppMessageBuffer, int32 * pdwMessageSize )
{
	int32 dwError = 0;
	uint8 *pSrcBuffer = NULL;
	int32 dwReqMsgSize = 0;
	int32 dwAlgorithmLen = 0;
	int32 dwNameLen = 0;
	uint8 *pMessageBuffer = NULL;
	int32 dwMessageSize = 0;
	uint8 *pOffset = NULL;
	int16 wnError, wError = 0;
	int16 wnFudge = 0;
	int16 wFudge = DNS_TEN_HOURS_IN_SECS;
	int16 wnOtherLen = 0, wOtherLen = 0;
	int32 dwBytesCopied = 0;
	int16 wnClass = 0, wClass = DNS_CLASS_ANY;
	int32 dwnTTL = 0, dwTTL = 0;
	int32 dwnTimeSigned, dwTimeSigned = 0;
	HANDLE hSendBuffer = ( HANDLE ) NULL;
	DNS_DOMAIN_NAME *pDomainName = NULL;
	DNS_DOMAIN_NAME *pAlgorithmName = NULL;
	int16 wTimePrefix = 0;
	int16 wnTimePrefix = 0;
	char szTsig[9];

	dwError = DNSDomainNameFromString( szKeyName, &pDomainName );
	BAIL_ON_ERROR( dwError );

	dwError = DNSGetDomainNameLength( pDomainName, &dwNameLen );
	BAIL_ON_ERROR( dwError );

	strncpy( szTsig, "gss-tsig", sizeof( szTsig ) );
	dwError = DNSDomainNameFromString( szTsig, &pAlgorithmName );
	BAIL_ON_ERROR( dwError );

	dwError = DNSGetDomainNameLength( pAlgorithmName, &dwAlgorithmLen );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSUpdateBuildRequestMessage( pDNSUpdateRequest,
					      &hSendBuffer );
	BAIL_ON_ERROR( dwError );

	dwReqMsgSize = DNSGetSendBufferContextSize( hSendBuffer );
	dwMessageSize += dwReqMsgSize;
	dwMessageSize += dwNameLen;
	dwMessageSize += sizeof( int16 );	/* class */
	dwMessageSize += sizeof( int32 );	/* TTL */
	dwMessageSize += dwAlgorithmLen;
	dwMessageSize += ( sizeof( int16 ) + sizeof( int32 ) );	/* Time Signed */
	dwMessageSize += sizeof( int16 );	/* Fudge */
	dwMessageSize += sizeof( int16 );	/* wError */
	dwMessageSize += sizeof( int16 );	/* Other Len */
	dwMessageSize += wOtherLen;

	dwError =
		DNSAllocateMemory( dwMessageSize,
				   ( void * ) &pMessageBuffer );
	BAIL_ON_ERROR( dwError );

	pOffset = pMessageBuffer;
	pSrcBuffer = DNSGetSendBufferContextBuffer( hSendBuffer );
	memcpy( pOffset, pSrcBuffer, dwReqMsgSize );
	pOffset += dwReqMsgSize;

	dwError =
		DNSCopyDomainName( pOffset, pAlgorithmName, &dwBytesCopied );
	BAIL_ON_ERROR( dwError );
	pOffset += dwBytesCopied;

	wnClass = htons( wClass );
	memcpy( pOffset, &wnClass, sizeof( int16 ) );
	pOffset += sizeof( int16 );

	dwnTTL = htonl( dwTTL );
	memcpy( pOffset, &dwnTTL, sizeof( int32 ) );
	pOffset += sizeof( int32 );


	wnTimePrefix = htons( wTimePrefix );
	memcpy( pOffset, &wnTimePrefix, sizeof( int16 ) );
	pOffset += sizeof( int16 );

	{
		time_t t;
		time(&t);
		dwTimeSigned = t;
	}
	dwnTimeSigned = htonl( dwTimeSigned );
	memcpy( pOffset, &dwnTimeSigned, sizeof( int32 ) );
	pOffset += sizeof( int32 );

	wnFudge = htons( wFudge );
	memcpy( pOffset, &wnFudge, sizeof( int16 ) );
	pOffset += sizeof( int16 );

	wnError = htons( wError );
	memcpy( pOffset, &wnError, sizeof( int16 ) );
	pOffset += sizeof( int16 );

	wnOtherLen = htons( wOtherLen );
	memcpy( pOffset, &wnOtherLen, sizeof( int16 ) );
	pOffset += sizeof( int16 );

	*ppMessageBuffer = pMessageBuffer;
	*pdwMessageSize = dwMessageSize;

	*pdwTimeSigned = dwTimeSigned;
	*pwFudge = wFudge;

	return dwError;

      error:

	if ( pMessageBuffer ) {
		DNSFreeMemory( pMessageBuffer );
	}

	*ppMessageBuffer = NULL;
	*pdwMessageSize = 0;
	*pdwTimeSigned = dwTimeSigned;
	*pwFudge = wFudge;
	return dwError;

}
