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

static int32 DNSStdAllocateResponse( DNS_RESPONSE ** ppDNSResponse )
{
	int32 dwError = 0;
	DNS_RESPONSE *pDNSResponse = NULL;

	dwError =
		DNSAllocateMemory( sizeof( DNS_RESPONSE ),
				   ( void * ) &pDNSResponse );
	BAIL_ON_ERROR( dwError );

	*ppDNSResponse = pDNSResponse;

	return dwError;

      error:

	*ppDNSResponse = NULL;

	return dwError;
}

/*********************************************************************
*********************************************************************/

static int32 DNSStdUnmarshallQuestionSection( HANDLE hReceiveBuffer,
				 int16 wQuestions,
				 DNS_QUESTION_RECORD *
				 **pppDNSQuestionRecords )
{
	int32 dwError = 0;
	int32 i = 0;
	int32 dwRead = 0;
	DNS_QUESTION_RECORD *pDNSQuestionRecord = NULL;
	DNS_QUESTION_RECORD **ppDNSQuestionRecords = NULL;
	int16 wnQueryClass = 0;
	int16 wnQueryType = 0;


	dwError =
		DNSAllocateMemory( wQuestions *
				   sizeof( DNS_QUESTION_RECORD * ),
				   ( void * ) &ppDNSQuestionRecords );
	BAIL_ON_ERROR( dwError );

	for ( i = 0; i < wQuestions; i++ ) {

		dwError =
			DNSAllocateMemory( sizeof( DNS_QUESTION_RECORD ),
					   ( void * ) &pDNSQuestionRecord );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSUnmarshallDomainName( hReceiveBuffer,
						 &pDNSQuestionRecord->
						 pDomainName );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSUnmarshallBuffer( hReceiveBuffer,
					     ( uint8 * ) & wnQueryType,
					     ( int32 ) sizeof( int16 ),
					     &dwRead );
		BAIL_ON_ERROR( dwError );
		pDNSQuestionRecord->wQueryType = ntohs( wnQueryType );

		dwError =
			DNSUnmarshallBuffer( hReceiveBuffer,
					     ( uint8 * ) & wnQueryClass,
					     ( int32 ) sizeof( int16 ),
					     &dwRead );
		BAIL_ON_ERROR( dwError );
		pDNSQuestionRecord->wQueryClass = ntohs( wnQueryClass );

		*( ppDNSQuestionRecords + i ) = pDNSQuestionRecord;
	}

	*pppDNSQuestionRecords = ppDNSQuestionRecords;
	return dwError;

      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

static int32 DNSStdUnmarshallAnswerSection( HANDLE hReceiveBuffer,
			       int16 wAnswers,
			       DNS_RR_RECORD * **pppDNSAnswerRRRecords )
{
	int32 dwError = 0;
	int32 i = 0;
	DNS_RR_RECORD *pDNSRRRecord = NULL;
	DNS_RR_RECORD **ppDNSAnswerRRRecords = NULL;
	DNS_RR_HEADER RRHeader = { 0 };
	DNS_RR_HEADER *pRRHeader = &RRHeader;
	uint8 *pRData = NULL;
	int32 dwRead = 0;

	dwError = DNSAllocateMemory( wAnswers * sizeof( DNS_RR_RECORD * ),
				     ( void * ) &ppDNSAnswerRRRecords );
	BAIL_ON_ERROR( dwError );

	for ( i = 0; i < wAnswers; i++ ) {

		memset( pRRHeader, 0, sizeof( DNS_RR_HEADER ) );
		dwError = DNSUnmarshallRRHeader( hReceiveBuffer, pRRHeader );
		BAIL_ON_ERROR( dwError );


		dwError =
			DNSUnmarshallRData( hReceiveBuffer,
					    pRRHeader->wRDataSize, &pRData,
					    &dwRead );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSAllocateMemory( sizeof( DNS_RR_RECORD ),
					   ( void * ) &pDNSRRRecord );
		BAIL_ON_ERROR( dwError );

		memcpy( &pDNSRRRecord->RRHeader, pRRHeader,
			sizeof( DNS_RR_HEADER ) );
		pDNSRRRecord->pRData = pRData;

		*( ppDNSAnswerRRRecords + i ) = pDNSRRRecord;
	}

	*pppDNSAnswerRRRecords = ppDNSAnswerRRRecords;

	return dwError;

      error:


	return dwError;
}

/*********************************************************************
*********************************************************************/

static int32 DNSStdUnmarshallAuthoritySection( HANDLE hReceiveBuffer,
				  int16 wAuthoritys,
				  DNS_RR_RECORD * **pppDNSAuthorityRRRecords )
{
	int32 dwError = 0;
	int32 i = 0;
	DNS_RR_RECORD *pDNSRRRecord = NULL;
	DNS_RR_RECORD **ppDNSAuthorityRRRecords = NULL;
	DNS_RR_HEADER RRHeader = { 0 };
	DNS_RR_HEADER *pRRHeader = &RRHeader;
	uint8 *pRData = NULL;
	int32 dwRead = 0;

	dwError = DNSAllocateMemory( wAuthoritys * sizeof( DNS_RR_RECORD * ),
				     ( void * ) &ppDNSAuthorityRRRecords );
	BAIL_ON_ERROR( dwError );

	for ( i = 0; i < wAuthoritys; i++ ) {

		memset( pRRHeader, 0, sizeof( DNS_RR_HEADER ) );
		dwError = DNSUnmarshallRRHeader( hReceiveBuffer, pRRHeader );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSUnmarshallRData( hReceiveBuffer,
					    pRRHeader->wRDataSize, &pRData,
					    &dwRead );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSAllocateMemory( sizeof( DNS_RR_RECORD ),
					   ( void * ) &pDNSRRRecord );
		BAIL_ON_ERROR( dwError );

		memcpy( &pDNSRRRecord->RRHeader, pRRHeader,
			sizeof( DNS_RR_HEADER ) );
		pDNSRRRecord->pRData = pRData;

		*( ppDNSAuthorityRRRecords + i ) = pDNSRRRecord;
	}

	*pppDNSAuthorityRRRecords = ppDNSAuthorityRRRecords;

	return dwError;

      error:

	return dwError;

}

/*********************************************************************
*********************************************************************/

static int32 DNSStdUnmarshallAdditionalSection( HANDLE hReceiveBuffer,
                                                int16 wAdditionals,
                                                DNS_RR_RECORD *
                                                **pppDNSAdditionalsRRRecords )
{
	int32 dwError = 0;
	int32 i = 0;
	DNS_RR_RECORD *pDNSRRRecord = NULL;
	DNS_RR_RECORD **ppDNSAdditionalRRRecords = NULL;
	DNS_RR_HEADER RRHeader = { 0 };
	DNS_RR_HEADER *pRRHeader = &RRHeader;
	uint8 *pRData = NULL;
	int32 dwRead = 0;

	dwError = DNSAllocateMemory( wAdditionals * sizeof( DNS_RR_RECORD * ),
				     ( void * ) &ppDNSAdditionalRRRecords );
	BAIL_ON_ERROR( dwError );

	for ( i = 0; i < wAdditionals; i++ ) {

		memset( pRRHeader, 0, sizeof( DNS_RR_HEADER ) );
		dwError = DNSUnmarshallRRHeader( hReceiveBuffer, pRRHeader );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSUnmarshallRData( hReceiveBuffer,
					    pRRHeader->wRDataSize, &pRData,
					    &dwRead );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSAllocateMemory( sizeof( DNS_RR_RECORD ),
					   ( void * ) &pDNSRRRecord );
		BAIL_ON_ERROR( dwError );

		memcpy( &pDNSRRRecord->RRHeader, pRRHeader,
			sizeof( DNS_RR_HEADER ) );
		pDNSRRRecord->pRData = pRData;


		*( ppDNSAdditionalRRRecords + i ) = pDNSRRRecord;
	}

      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSStdReceiveStdResponse( HANDLE hDNSHandle, DNS_RESPONSE ** ppDNSResponse )
{
	DNS_RESPONSE *pDNSResponse = NULL;
	int32 dwError = 0;
	int16 wnIdentification, wIdentification = 0;
	int16 wnParameter, wParameter = 0;
	int16 wnQuestions, wQuestions = 0;
	int16 wnAnswers, wAnswers = 0;
	int16 wnAdditionals, wAdditionals = 0;
	int16 wnAuthoritys, wAuthoritys = 0;
	int32 dwRead = 0;
	DNS_RR_RECORD **ppDNSAnswerRecords = NULL;
	DNS_RR_RECORD **ppDNSAdditionalRecords = NULL;
	DNS_RR_RECORD **ppDNSAuthorityRecords = NULL;
	DNS_QUESTION_RECORD **ppDNSQuestionRecords = NULL;
	HANDLE hRecvBuffer = ( HANDLE ) NULL;

	dwError = DNSCreateReceiveBuffer( &hRecvBuffer );
	BAIL_ON_ERROR( dwError );

	dwError = DNSReceiveBufferContext( hDNSHandle, hRecvBuffer, &dwRead );
	BAIL_ON_ERROR( dwError );

#if 0
	dwError = DNSDumpRecvBufferContext( hRecvBuffer );
	BAIL_ON_ERROR( dwError );
#endif

	dwError =
		DNSUnmarshallBuffer( hRecvBuffer,
				     ( uint8 * ) & wnIdentification,
				     sizeof( int16 ), &dwRead );
	BAIL_ON_ERROR( dwError );
	wIdentification = ntohs( wnIdentification );

	dwError =
		DNSUnmarshallBuffer( hRecvBuffer, ( uint8 * ) & wnParameter,
				     sizeof( int16 ), &dwRead );
	BAIL_ON_ERROR( dwError );
	wParameter = ntohs( wnParameter );


	dwError =
		DNSUnmarshallBuffer( hRecvBuffer, ( uint8 * ) & wnQuestions,
				     sizeof( int16 ), &dwRead );
	BAIL_ON_ERROR( dwError );
	wQuestions = ntohs( wnQuestions );


	dwError =
		DNSUnmarshallBuffer( hRecvBuffer, ( uint8 * ) & wnAnswers,
				     sizeof( int16 ), &dwRead );
	BAIL_ON_ERROR( dwError );
	wAnswers = ntohs( wnAnswers );


	dwError =
		DNSUnmarshallBuffer( hRecvBuffer, ( uint8 * ) & wnAuthoritys,
				     sizeof( int16 ), &dwRead );
	BAIL_ON_ERROR( dwError );
	wAuthoritys = ntohs( wnAuthoritys );

	dwError =
		DNSUnmarshallBuffer( hRecvBuffer, ( uint8 * ) & wnAdditionals,
				     sizeof( int16 ), &dwRead );
	BAIL_ON_ERROR( dwError );
	wAdditionals = ntohs( wnAdditionals );


	if ( wQuestions ) {
		dwError =
			DNSStdUnmarshallQuestionSection( hRecvBuffer,
							 wQuestions,
							 &ppDNSQuestionRecords );
		BAIL_ON_ERROR( dwError );
	}

	if ( wAnswers ) {
		dwError =
			DNSStdUnmarshallAnswerSection( hRecvBuffer, wAnswers,
						       &ppDNSAnswerRecords );
		BAIL_ON_ERROR( dwError );
	}

	if ( wAuthoritys ) {
		dwError =
			DNSStdUnmarshallAuthoritySection( hRecvBuffer,
							  wAuthoritys,
							  &ppDNSAuthorityRecords );
		BAIL_ON_ERROR( dwError );
	}

	if ( wAdditionals ) {
		dwError =
			DNSStdUnmarshallAdditionalSection( hRecvBuffer,
							   wAdditionals,
							   &ppDNSAdditionalRecords );
		BAIL_ON_ERROR( dwError );
	}

	dwError = DNSStdAllocateResponse( &pDNSResponse );
	BAIL_ON_ERROR( dwError );

	pDNSResponse->wIdentification = wIdentification;
	pDNSResponse->wParameter = wParameter;
	pDNSResponse->wQuestions = wQuestions;
	pDNSResponse->wAnswers = wAnswers;
	pDNSResponse->wAuthoritys = wAuthoritys;
	pDNSResponse->wAdditionals = wAdditionals;

	pDNSResponse->ppQuestionRRSet = ppDNSQuestionRecords;
	pDNSResponse->ppAnswerRRSet = ppDNSAnswerRecords;
	pDNSResponse->ppAuthorityRRSet = ppDNSAuthorityRecords;
	pDNSResponse->ppAdditionalRRSet = ppDNSAdditionalRecords;

	*ppDNSResponse = pDNSResponse;


      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSUnmarshallDomainName( HANDLE hRecvBuffer, DNS_DOMAIN_NAME ** ppDomainName )
{
	int32 dwError = 0;
	DNS_DOMAIN_LABEL *pLabel = NULL;
	DNS_DOMAIN_LABEL *pLabelList = NULL;
	DNS_DOMAIN_NAME *pDomainName = NULL;
	char *pszLabel = NULL;
	char szLabel[65];
	uint8 uLen = 0;
	int32 dwRead = 0;
	uint8 uLen1, uLen2 = 0;
	int16 wnOffset, wOffset = 0;

	dwError =
		DNSUnmarshallBuffer( hRecvBuffer, &uLen1, sizeof( char ),
				     &dwRead );
	BAIL_ON_ERROR( dwError );
	if ( uLen1 & 0xC0 ) {

		uLen1 |= 0x3F;
		dwError =
			DNSUnmarshallBuffer( hRecvBuffer, &uLen2,
					     sizeof( char ), &dwRead );
		BAIL_ON_ERROR( dwError );

		memcpy( ( uint8 * ) & wnOffset, &uLen1, sizeof( char ) );
		memcpy( ( uint8 * ) & wnOffset + 1, &uLen2, sizeof( char ) );
		wOffset = ntohs( wnOffset );

		dwError =
			DNSUnmarshallDomainNameAtOffset( hRecvBuffer, wOffset,
							 &pDomainName );
		BAIL_ON_ERROR( dwError );
		*ppDomainName = pDomainName;

		return dwError;

	} else {

		dwError = DNSReceiveBufferMoveBackIndex( hRecvBuffer, 1 );
		BAIL_ON_ERROR( dwError );

		while ( 1 ) {


			dwError =
				DNSUnmarshallBuffer( hRecvBuffer, &uLen,
						     sizeof( char ),
						     &dwRead );
			BAIL_ON_ERROR( dwError );
			if ( uLen == 0 ) {
				break;
			}

			memset( szLabel, 0, 65 );
			dwError =
				DNSUnmarshallBuffer( hRecvBuffer,
						     ( uint8 * ) szLabel,
						     uLen, &dwRead );

			dwError = DNSAllocateString( szLabel, &pszLabel );
			BAIL_ON_ERROR( dwError );

			dwError =
				DNSAllocateMemory( sizeof( DNS_DOMAIN_LABEL ),
						   ( void * ) &pLabel );
			BAIL_ON_ERROR( dwError );

			pLabel->pszLabel = pszLabel;
			dwError =
				DNSAppendLabel( pLabelList, pLabel,
						&pLabelList );
			BAIL_ON_ERROR( dwError );
		}

	}

	dwError =
		DNSAllocateMemory( sizeof( DNS_DOMAIN_NAME ),
				   ( void * ) &pDomainName );
	BAIL_ON_ERROR( dwError );
	pDomainName->pLabelList = pLabelList;

	*ppDomainName = pDomainName;

	return dwError;

      error:

	*ppDomainName = NULL;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSUnmarshallRRHeader( HANDLE hRecvBuffer, DNS_RR_HEADER * pRRHeader )
{
	int32 dwError = 0;
	int32 dwRead = 0;
	int16 wnType = 0;
	int16 wnClass = 0;
	int16 wnRDataSize = 0;
	int32 dwnTTL = 0;

	dwError =
		DNSUnmarshallDomainName( hRecvBuffer,
					 &pRRHeader->pDomainName );
	BAIL_ON_ERROR( dwError );


	dwError =
		DNSUnmarshallBuffer( hRecvBuffer, ( uint8 * ) & wnType,
				     sizeof( int16 ), &dwRead );
	BAIL_ON_ERROR( dwError );
	pRRHeader->wType = ntohs( wnType );


	dwError =
		DNSUnmarshallBuffer( hRecvBuffer, ( uint8 * ) & wnClass,
				     sizeof( int16 ), &dwRead );
	BAIL_ON_ERROR( dwError );
	pRRHeader->wClass = ntohs( wnClass );

	dwError =
		DNSUnmarshallBuffer( hRecvBuffer, ( uint8 * ) & dwnTTL,
				     sizeof( int32 ), &dwRead );
	BAIL_ON_ERROR( dwError );
	pRRHeader->dwTTL = ntohl( dwnTTL );

	dwError =
		DNSUnmarshallBuffer( hRecvBuffer, ( uint8 * ) & wnRDataSize,
				     sizeof( int16 ), &dwRead );
	BAIL_ON_ERROR( dwError );
	pRRHeader->wRDataSize = htons( wnRDataSize );

      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSUnmarshallRData( HANDLE hRecvBuffer,
		    int32 dwSize, uint8 ** ppRData, int32 * pdwRead )
{
	int32 dwError = 0;
	uint8 *pMemory = NULL;

	dwError = DNSAllocateMemory( dwSize, ( void * ) &pMemory );
	BAIL_ON_ERROR( dwError );
	dwError =
		DNSUnmarshallBuffer( hRecvBuffer, ( uint8 * ) pMemory, dwSize,
				     pdwRead );
	BAIL_ON_ERROR( dwError );

	*ppRData = pMemory;

	return dwError;

      error:

	if ( pMemory ) {
		DNSFreeMemory( pMemory );
	}

	*ppRData = NULL;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSUpdateGetResponseCode( DNS_UPDATE_RESPONSE * pDNSUpdateResponse,
			  int32 * pdwResponseCode )
{
	int32 dwError = 0;

	*pdwResponseCode =
		MapDNSResponseCodes( pDNSUpdateResponse->wParameter );

	return dwError;
}

