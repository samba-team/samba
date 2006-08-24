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

#include "dns.h"

/*********************************************************************
*********************************************************************/

static int32 DNSStdMarshallQuestionSection( HANDLE hSendBuffer,
			       DNS_QUESTION_RECORD ** ppDNSQuestionRecords,
			       int16 wQuestions )
{
	int32 dwError = 0;
	int32 i = 0;
	int32 dwRead = 0;
	DNS_QUESTION_RECORD *pDNSQuestionRecord = NULL;
	int16 wnQueryType = 0;
	int16 wnQueryClass = 0;

	for ( i = 0; i < wQuestions; i++ ) {

		pDNSQuestionRecord = *( ppDNSQuestionRecords + i );
		dwError =
			DNSMarshallDomainName( hSendBuffer,
					       pDNSQuestionRecord->
					       pDomainName );
		BAIL_ON_ERROR( dwError );

		wnQueryType = htons( pDNSQuestionRecord->wQueryType );
		dwError =
			DNSMarshallBuffer( hSendBuffer,
					   ( uint8 * ) & wnQueryType,
					   ( int32 ) sizeof( int16 ),
					   &dwRead );
		BAIL_ON_ERROR( dwError );

		wnQueryClass = htons( pDNSQuestionRecord->wQueryClass );
		dwError =
			DNSMarshallBuffer( hSendBuffer,
					   ( uint8 * ) & wnQueryClass,
					   ( int32 ) sizeof( int16 ),
					   &dwRead );
		BAIL_ON_ERROR( dwError );

		pDNSQuestionRecord++;
	}

      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

static int32 DNSStdMarshallAnswerSection( HANDLE hSendBuffer,
			     DNS_RR_RECORD ** ppDNSAnswerRRRecords,
			     int16 wAnswers )
{
	int32 dwError = 0;
	int32 i = 0;
	DNS_RR_RECORD *pDNSAnswerRRRecord = NULL;


	for ( i = 0; i < wAnswers; i++ ) {

		pDNSAnswerRRRecord = *( ppDNSAnswerRRRecords + i );

		dwError =
			DNSMarshallRRHeader( hSendBuffer,
					     pDNSAnswerRRRecord );
		BAIL_ON_ERROR( dwError );

		dwError = DNSMarshallRData( hSendBuffer, pDNSAnswerRRRecord );
		BAIL_ON_ERROR( dwError );

		pDNSAnswerRRRecord++;

	}
      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

static int32 DNSStdMarshallAuthoritySection( HANDLE hSendBuffer,
				DNS_RR_RECORD ** ppDNSAuthorityRRRecords,
				int16 wAuthoritys )
{
	int32 dwError = 0;
	int32 i = 0;

	DNS_RR_RECORD *pDNSAuthorityRRRecord = NULL;

	for ( i = 0; i < wAuthoritys; i++ ) {

		pDNSAuthorityRRRecord = *( ppDNSAuthorityRRRecords + i );

		dwError =
			DNSMarshallRRHeader( hSendBuffer,
					     pDNSAuthorityRRRecord );

		dwError = DNSMarshallRData( hSendBuffer,
					    pDNSAuthorityRRRecord );
		BAIL_ON_ERROR( dwError );

	}
      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

static int32 DNSStdMarshallAdditionalSection( HANDLE hSendBuffer,
				 DNS_RR_RECORD ** ppDNSAdditionalsRRRecords,
				 int16 wAdditionals )
{
	int32 dwError = 0;
	int32 i = 0;
	DNS_RR_RECORD *pDNSAdditionalRRRecord = NULL;

	for ( i = 0; i < wAdditionals; i++ ) {

		pDNSAdditionalRRRecord = *( ppDNSAdditionalsRRRecords + i );

		dwError =
			DNSMarshallRRHeader( hSendBuffer,
					     pDNSAdditionalRRRecord );
		BAIL_ON_ERROR( dwError );

		dwError = DNSMarshallRData( hSendBuffer,
					    pDNSAdditionalRRRecord );
		BAIL_ON_ERROR( dwError );

	}

      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

static int32 DNSBuildRequestMessage( DNS_REQUEST * pDNSRequest, HANDLE * phSendBuffer )
{
	int32 dwError = 0;
	char DNSMessageHeader[12];
	int16 wnIdentification = 0;
	int16 wnParameter = 0;
	int16 wnQuestions = 0;
	int16 wnAnswers = 0;
	int16 wnAuthoritys = 0;
	int16 wnAdditionals = 0;
	int32 dwRead = 0;
	HANDLE hSendBuffer = ( HANDLE ) NULL;

	dwError = DNSCreateSendBuffer( &hSendBuffer );
	BAIL_ON_ERROR( dwError );

	wnIdentification = htons( pDNSRequest->wIdentification );
	memcpy( DNSMessageHeader, ( char * ) &wnIdentification, 2 );

	wnParameter = htons( pDNSRequest->wParameter );
	memcpy( DNSMessageHeader + 2, ( char * ) &wnParameter, 2 );

	wnQuestions = htons( pDNSRequest->wQuestions );
	memcpy( DNSMessageHeader + 4, ( char * ) &wnQuestions, 2 );

	wnAnswers = htons( pDNSRequest->wAnswers );
	memcpy( DNSMessageHeader + 6, ( char * ) &wnAnswers, 2 );

	wnAuthoritys = htons( pDNSRequest->wAuthoritys );
	memcpy( DNSMessageHeader + 8, ( char * ) &wnAuthoritys, 2 );

	wnAdditionals = htons( pDNSRequest->wAdditionals );
	memcpy( DNSMessageHeader + 10, ( char * ) &wnAdditionals, 2 );

	dwError =
		DNSMarshallBuffer( hSendBuffer, ( uint8 * ) DNSMessageHeader,
				   12, &dwRead );
	BAIL_ON_ERROR( dwError );

	if ( pDNSRequest->wQuestions ) {
		dwError =
			DNSStdMarshallQuestionSection( hSendBuffer,
						       pDNSRequest->
						       ppQuestionRRSet,
						       pDNSRequest->
						       wQuestions );
		BAIL_ON_ERROR( dwError );
	}

	if ( pDNSRequest->wAnswers ) {
		dwError =
			DNSStdMarshallAnswerSection( hSendBuffer,
						     pDNSRequest->
						     ppAnswerRRSet,
						     pDNSRequest->wAnswers );
		BAIL_ON_ERROR( dwError );
	}

	if ( pDNSRequest->wAuthoritys ) {
		dwError =
			DNSStdMarshallAuthoritySection( hSendBuffer,
							pDNSRequest->
							ppAuthorityRRSet,
							pDNSRequest->
							wAuthoritys );
		BAIL_ON_ERROR( dwError );
	}

	if ( pDNSRequest->wAdditionals ) {
		dwError =
			DNSStdMarshallAdditionalSection( hSendBuffer,
							 pDNSRequest->
							 ppAdditionalRRSet,
							 pDNSRequest->
							 wAdditionals );
		BAIL_ON_ERROR( dwError );
	}
#if 0
	DNSDumpSendBufferContext( hSendBuffer );
#endif
	*phSendBuffer = hSendBuffer;

	return dwError;

      error:

	if ( hSendBuffer ) {
		DNSFreeSendBufferContext( hSendBuffer );
	}

	*phSendBuffer = ( HANDLE ) NULL;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSStdSendStdRequest2( HANDLE hDNSServer, DNS_REQUEST * pDNSRequest )
{
	int32 dwError = 0;
	int32 dwBytesSent = 0;
	HANDLE hSendBuffer = ( HANDLE ) NULL;

	dwError = DNSBuildRequestMessage( pDNSRequest, &hSendBuffer );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSSendBufferContext( hDNSServer, hSendBuffer, &dwBytesSent );
	BAIL_ON_ERROR( dwError );

      error:

	if ( hSendBuffer ) {
		DNSFreeSendBufferContext( hSendBuffer );
	}

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSMarshallDomainName( HANDLE hSendBuffer, DNS_DOMAIN_NAME * pDomainName )
{
	int32 dwError = 0;
	DNS_DOMAIN_LABEL *pTemp = NULL;
	int32 dwLen = 0;
	int32 dwSent = 0;
	char uEndChar = 0;

	pTemp = pDomainName->pLabelList;
	while ( pTemp ) {
		dwLen = ( int32 ) strlen( pTemp->pszLabel );
		dwError =
			DNSMarshallBuffer( hSendBuffer, ( uint8 * ) & dwLen,
					   sizeof( char ), &dwSent );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSMarshallBuffer( hSendBuffer,
					   ( uint8 * ) pTemp->pszLabel, dwLen,
					   &dwSent );
		BAIL_ON_ERROR( dwError );
		pTemp = pTemp->pNext;
	}
	DNSMarshallBuffer( hSendBuffer, ( uint8 * ) & uEndChar,
			   sizeof( char ), &dwSent );

      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSMarshallRRHeader( HANDLE hSendBuffer, DNS_RR_RECORD * pDNSRecord )
{
	int32 dwError = 0;
	int32 dwRead = 0;
	int16 wnType = 0;
	int16 wnClass = 0;
	int16 wnRDataSize = 0;
	int32 dwnTTL = 0;

	dwError =
		DNSMarshallDomainName( hSendBuffer,
				       pDNSRecord->RRHeader.pDomainName );
	BAIL_ON_ERROR( dwError );

	wnType = htons( pDNSRecord->RRHeader.wType );
	dwError =
		DNSMarshallBuffer( hSendBuffer, ( uint8 * ) & wnType,
				   sizeof( int16 ), &dwRead );
	BAIL_ON_ERROR( dwError );

	wnClass = htons( pDNSRecord->RRHeader.wClass );
	dwError =
		DNSMarshallBuffer( hSendBuffer, ( uint8 * ) & wnClass,
				   sizeof( int16 ), &dwRead );
	BAIL_ON_ERROR( dwError );

	dwnTTL = htonl( pDNSRecord->RRHeader.dwTTL );
	dwError =
		DNSMarshallBuffer( hSendBuffer, ( uint8 * ) & dwnTTL,
				   sizeof( int32 ), &dwRead );
	BAIL_ON_ERROR( dwError );

	wnRDataSize = htons( pDNSRecord->RRHeader.wRDataSize );
	dwError =
		DNSMarshallBuffer( hSendBuffer, ( uint8 * ) & wnRDataSize,
				   sizeof( int16 ), &dwRead );
	BAIL_ON_ERROR( dwError );

      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSMarshallRData( HANDLE hSendBuffer, DNS_RR_RECORD * pDNSRecord )
{
	int32 dwError = 0;
	int32 dwWritten = 0;

	dwError =
		DNSMarshallBuffer( hSendBuffer, pDNSRecord->pRData,
				   pDNSRecord->RRHeader.wRDataSize,
				   &dwWritten );
	BAIL_ON_ERROR( dwError );

      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSStdAddQuestionSection( DNS_REQUEST * pDNSRequest,
			  DNS_QUESTION_RECORD * pDNSQuestion )
{
	int32 dwNumQuestions = 0;
	int32 dwError = 0;

	dwNumQuestions = pDNSRequest->wQuestions;

	dwError = DNSReallocMemory( ( uint8 * ) pDNSRequest->ppQuestionRRSet,
				    ( void * ) &pDNSRequest->ppQuestionRRSet,
				    ( dwNumQuestions +
				      1 ) * sizeof( DNS_QUESTION_RECORD * )
		 );
	BAIL_ON_ERROR( dwError );

	*( pDNSRequest->ppQuestionRRSet + dwNumQuestions ) = pDNSQuestion;

	pDNSRequest->wQuestions += 1;

      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSStdAddAdditionalSection( DNS_REQUEST * pDNSRequest,
			    DNS_RR_RECORD * pDNSRecord )
{
	int32 dwNumAdditionals = 0;
	int32 dwError = 0;

	dwNumAdditionals = pDNSRequest->wAdditionals;
	dwError = DNSReallocMemory( pDNSRequest->ppAdditionalRRSet,
				    ( void * ) &pDNSRequest->
				    ppAdditionalRRSet,
				    ( dwNumAdditionals +
				      1 ) * sizeof( DNS_RR_RECORD * ) );
	BAIL_ON_ERROR( dwError );

	*( pDNSRequest->ppAdditionalRRSet + dwNumAdditionals ) = pDNSRecord;

	pDNSRequest->wAdditionals += 1;

      error:
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSStdCreateStdRequest( DNS_REQUEST ** ppDNSRequest )
{
	int32 dwError = 0;
	DNS_REQUEST *pDNSRequest = NULL;

#if 0
	int16 wRecursionDesired = RECURSION_DESIRED;
	int16 wParameter = QR_QUERY;
	int16 wOpcode = OPCODE_QUERY;
#endif
	dwError =
		DNSAllocateMemory( sizeof( DNS_REQUEST ),
				   ( void * ) &pDNSRequest );
	BAIL_ON_ERROR( dwError );

	dwError = DNSGenerateIdentifier( &pDNSRequest->wIdentification );
	BAIL_ON_ERROR( dwError );

/*	
	wOpcode <<= 1;
	wRecursionDesired <<= 7;
	wParameter |= wOpcode;
	wParameter |= wRecursionDesired;
*/
	pDNSRequest->wParameter = 0x00;

	*ppDNSRequest = pDNSRequest;

	return dwError;

      error:

	*ppDNSRequest = NULL;
	return dwError;
}
