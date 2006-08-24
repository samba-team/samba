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

static int32 DNSUpdateAllocateResponse( DNS_UPDATE_RESPONSE ** ppDNSResponse )
{
	int32 dwError = 0;
	DNS_UPDATE_RESPONSE *pDNSResponse = NULL;

	dwError =
		DNSAllocateMemory( sizeof( DNS_UPDATE_RESPONSE ),
				   ( void ** ) &pDNSResponse );
	BAIL_ON_ERROR( dwError );

	*ppDNSResponse = pDNSResponse;

	return dwError;

      error:

	*ppDNSResponse = NULL;

	return dwError;
}

/*********************************************************************
*********************************************************************/

static int32 DNSUpdateUnmarshallAdditionalSection( HANDLE hReceiveBuffer,
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
	uint8 *pRRData = NULL;
	int32 dwRead = 0;

	dwError = DNSAllocateMemory( wAdditionals * sizeof( DNS_RR_RECORD * ),
				     ( void ** ) &ppDNSAdditionalRRRecords );
	BAIL_ON_ERROR( dwError );

	for ( i = 0; i < wAdditionals; i++ ) {

		memset( pRRHeader, 0, sizeof( DNS_RR_HEADER ) );
		dwError = DNSUnmarshallRRHeader( hReceiveBuffer, pRRHeader );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSUnmarshallRData( hReceiveBuffer,
					    pRRHeader->wRDataSize, &pRRData,
					    &dwRead );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSAllocateMemory( sizeof( DNS_RR_RECORD ),
					   ( void ** ) &pDNSRRRecord );
		BAIL_ON_ERROR( dwError );

		memcpy( &pDNSRRRecord->RRHeader, pRRHeader,
			sizeof( DNS_RR_HEADER ) );
		pDNSRRRecord->pRData = pRRData;

		*( ppDNSAdditionalRRRecords + i ) = pDNSRRRecord;
	}

      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

static int32 DNSUpdateUnmarshallPRSection( HANDLE hReceiveBuffer,
			      int16 wPRs,
			      DNS_RR_RECORD * **pppDNSPRRRRecords )
{
	int32 dwError = 0;
	int32 i = 0;
	DNS_RR_RECORD *pDNSRRRecord = NULL;
	DNS_RR_RECORD **ppDNSPRRRRecords = NULL;
	DNS_RR_HEADER RRHeader = { 0 };
	DNS_RR_HEADER *pRRHeader = &RRHeader;
	uint8 *pRRData = NULL;
	int32 dwRead = 0;

	dwError = DNSAllocateMemory( wPRs * sizeof( DNS_RR_RECORD * ),
				     ( void ** ) &ppDNSPRRRRecords );
	BAIL_ON_ERROR( dwError );

	for ( i = 0; i < wPRs; i++ ) {

		memset( pRRHeader, 0, sizeof( DNS_RR_HEADER ) );
		dwError = DNSUnmarshallRRHeader( hReceiveBuffer, pRRHeader );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSUnmarshallRData( hReceiveBuffer,
					    pRRHeader->wRDataSize, &pRRData,
					    &dwRead );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSAllocateMemory( sizeof( DNS_RR_RECORD ),
					   ( void ** ) &pDNSRRRecord );
		BAIL_ON_ERROR( dwError );

		memcpy( &pDNSRRRecord->RRHeader, pRRHeader,
			sizeof( DNS_RR_HEADER ) );
		pDNSRRRecord->pRData = pRRData;

		*( ppDNSPRRRRecords + i ) = pDNSRRRecord;
	}

	*pppDNSPRRRRecords = ppDNSPRRRRecords;

	return dwError;

      error:


	return dwError;
}

/*********************************************************************
*********************************************************************/

static int32 DNSUpdateUnmarshallUpdateSection( HANDLE hReceiveBuffer,
				  int16 wUpdates,
				  DNS_RR_RECORD * **pppDNSUpdateRRRecords )
{
	int32 dwError = 0;
	int32 i = 0;
	DNS_RR_RECORD *pDNSRRRecord = NULL;
	DNS_RR_RECORD **ppDNSUpdateRRRecords = NULL;
	DNS_RR_HEADER RRHeader = { 0 };
	DNS_RR_HEADER *pRRHeader = &RRHeader;
	uint8 *pRRData = NULL;
	int32 dwRead = 0;

	dwError = DNSAllocateMemory( wUpdates * sizeof( DNS_RR_RECORD * ),
				     ( void ** ) &ppDNSUpdateRRRecords );
	BAIL_ON_ERROR( dwError );

	for ( i = 0; i < wUpdates; i++ ) {

		memset( pRRHeader, 0, sizeof( DNS_RR_HEADER ) );
		dwError = DNSUnmarshallRRHeader( hReceiveBuffer, pRRHeader );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSUnmarshallRData( hReceiveBuffer,
					    pRRHeader->wRDataSize, &pRRData,
					    &dwRead );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSAllocateMemory( sizeof( DNS_RR_RECORD ),
					   ( void ** ) &pDNSRRRecord );
		BAIL_ON_ERROR( dwError );

		memcpy( &pDNSRRRecord->RRHeader, pRRHeader,
			sizeof( DNS_RR_HEADER ) );
		pDNSRRRecord->pRData = pRRData;

		*( ppDNSUpdateRRRecords + i ) = pDNSRRRecord;
	}

	*pppDNSUpdateRRRecords = ppDNSUpdateRRRecords;

	return dwError;

      error:

	return dwError;

}

/*********************************************************************
*********************************************************************/

static int32 DNSUpdateUnmarshallZoneSection( HANDLE hReceiveBuffer,
				int16 wZones,
				DNS_ZONE_RECORD * **pppDNSZoneRecords )
{
	int32 dwError = 0;
	int32 i = 0;
	int32 dwRead = 0;
	DNS_ZONE_RECORD *pDNSZoneRecord = NULL;
	DNS_ZONE_RECORD **ppDNSZoneRecords = NULL;
	int16 wnZoneClass = 0;
	int16 wnZoneType = 0;


	dwError = DNSAllocateMemory( wZones * sizeof( DNS_ZONE_RECORD * ),
				     ( void ** ) &ppDNSZoneRecords );
	BAIL_ON_ERROR( dwError );

	for ( i = 0; i < wZones; i++ ) {

		dwError =
			DNSAllocateMemory( sizeof( DNS_ZONE_RECORD ),
					   ( void ** ) &pDNSZoneRecord );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSUnmarshallDomainName( hReceiveBuffer,
						 &pDNSZoneRecord->
						 pDomainName );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSUnmarshallBuffer( hReceiveBuffer,
					     ( uint8 * ) & wnZoneType,
					     ( int32 ) sizeof( int16 ),
					     &dwRead );
		BAIL_ON_ERROR( dwError );
		pDNSZoneRecord->wZoneType = ntohs( wnZoneType );

		dwError =
			DNSUnmarshallBuffer( hReceiveBuffer,
					     ( uint8 * ) & wnZoneClass,
					     ( int32 ) sizeof( int16 ),
					     &dwRead );
		BAIL_ON_ERROR( dwError );
		pDNSZoneRecord->wZoneClass = ntohs( wnZoneClass );

		*( ppDNSZoneRecords + i ) = pDNSZoneRecord;
	}

	*pppDNSZoneRecords = ppDNSZoneRecords;
	return dwError;

      error:

	return dwError;
}


/*********************************************************************
*********************************************************************/

int32 DNSUpdateReceiveUpdateResponse( HANDLE hDNSHandle,
				DNS_UPDATE_RESPONSE ** ppDNSResponse )
{
	DNS_UPDATE_RESPONSE *pDNSResponse = NULL;
	int32 dwError = 0;
	int16 wnIdentification, wIdentification = 0;
	int16 wnParameter, wParameter = 0;
	int16 wnZones, wZones = 0;
	int16 wnPRs, wPRs = 0;
	int16 wnAdditionals, wAdditionals = 0;
	int16 wnUpdates, wUpdates = 0;
	int32 dwRead = 0;
	DNS_RR_RECORD **ppDNSPRRecords = NULL;
	DNS_RR_RECORD **ppDNSAdditionalRecords = NULL;
	DNS_RR_RECORD **ppDNSUpdateRecords = NULL;
	DNS_ZONE_RECORD **ppDNSZoneRecords = NULL;
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
		DNSUnmarshallBuffer( hRecvBuffer, ( uint8 * ) & wnZones,
				     sizeof( int16 ), &dwRead );
	BAIL_ON_ERROR( dwError );
	wZones = ntohs( wnZones );


	dwError =
		DNSUnmarshallBuffer( hRecvBuffer, ( uint8 * ) & wnPRs,
				     sizeof( int16 ), &dwRead );
	BAIL_ON_ERROR( dwError );
	wPRs = ntohs( wnPRs );


	dwError =
		DNSUnmarshallBuffer( hRecvBuffer, ( uint8 * ) & wnUpdates,
				     sizeof( int16 ), &dwRead );
	BAIL_ON_ERROR( dwError );
	wUpdates = ntohs( wnUpdates );

	dwError =
		DNSUnmarshallBuffer( hRecvBuffer, ( uint8 * ) & wnAdditionals,
				     sizeof( int16 ), &dwRead );
	BAIL_ON_ERROR( dwError );
	wAdditionals = ntohs( wnAdditionals );


	if ( wZones ) {
		dwError =
			DNSUpdateUnmarshallZoneSection( hRecvBuffer, wZones,
							&ppDNSZoneRecords );
		BAIL_ON_ERROR( dwError );
	}

	if ( wPRs ) {
		dwError =
			DNSUpdateUnmarshallPRSection( hRecvBuffer, wPRs,
						      &ppDNSPRRecords );
		BAIL_ON_ERROR( dwError );
	}

	if ( wUpdates ) {
		dwError =
			DNSUpdateUnmarshallUpdateSection( hRecvBuffer,
							  wUpdates,
							  &ppDNSUpdateRecords );
		BAIL_ON_ERROR( dwError );
	}

	if ( wAdditionals ) {
		dwError =
			DNSUpdateUnmarshallAdditionalSection( hRecvBuffer,
							      wAdditionals,
							      &ppDNSAdditionalRecords );
		BAIL_ON_ERROR( dwError );
	}

	dwError = DNSUpdateAllocateResponse( &pDNSResponse );
	BAIL_ON_ERROR( dwError );

	pDNSResponse->wIdentification = wIdentification;
	pDNSResponse->wParameter = wParameter;
	pDNSResponse->wZones = wZones;
	pDNSResponse->wPRs = wPRs;
	pDNSResponse->wUpdates = wUpdates;
	pDNSResponse->wAdditionals = wAdditionals;

	pDNSResponse->ppZoneRRSet = ppDNSZoneRecords;
	pDNSResponse->ppPRRRSet = ppDNSPRRecords;
	pDNSResponse->ppUpdateRRSet = ppDNSUpdateRecords;
	pDNSResponse->ppAdditionalRRSet = ppDNSAdditionalRecords;

	*ppDNSResponse = pDNSResponse;


      error:

	return dwError;
}

