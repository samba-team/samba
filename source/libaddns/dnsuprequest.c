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

static int32 DNSUpdateMarshallZoneSection( HANDLE hSendBuffer,
			      DNS_ZONE_RECORD ** ppDNSZoneRecords,
			      int16 wZones )
{
	int32 dwError = 0;
	int32 i = 0;
	int32 dwRead = 0;
	DNS_ZONE_RECORD *pDNSZoneRecord = NULL;
	int16 wnZoneType = 0;
	int16 wnZoneClass = 0;

	for ( i = 0; i < wZones; i++ ) {

		pDNSZoneRecord = *( ppDNSZoneRecords + i );
		dwError =
			DNSMarshallDomainName( hSendBuffer,
					       pDNSZoneRecord->pDomainName );
		BAIL_ON_ERROR( dwError );

		wnZoneType = htons( pDNSZoneRecord->wZoneType );
		dwError =
			DNSMarshallBuffer( hSendBuffer,
					   ( uint8 * ) & wnZoneType,
					   ( int32 ) sizeof( int16 ),
					   &dwRead );
		BAIL_ON_ERROR( dwError );

		wnZoneClass = htons( pDNSZoneRecord->wZoneClass );
		dwError =
			DNSMarshallBuffer( hSendBuffer,
					   ( uint8 * ) & wnZoneClass,
					   ( int32 ) sizeof( int16 ),
					   &dwRead );
		BAIL_ON_ERROR( dwError );

		pDNSZoneRecord++;
	}

      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

static int32 DNSUpdateMarshallPRSection( HANDLE hSendBuffer,
			    DNS_RR_RECORD ** ppDNSPRRRRecords, int16 wPRs )
{
	int32 dwError = 0;
	int32 i = 0;
	DNS_RR_RECORD *pDNSPRRRRecord = NULL;


	for ( i = 0; i < wPRs; i++ ) {

		pDNSPRRRRecord = *( ppDNSPRRRRecords + i );

		dwError = DNSMarshallRRHeader( hSendBuffer, pDNSPRRRRecord );
		BAIL_ON_ERROR( dwError );

		if ( pDNSPRRRRecord->RRHeader.wRDataSize ) {
			dwError =
				DNSMarshallRData( hSendBuffer,
						  pDNSPRRRRecord );
			BAIL_ON_ERROR( dwError );
		}
	}
      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

static int32 DNSUpdateMarshallUpdateSection( HANDLE hSendBuffer,
				DNS_RR_RECORD ** ppDNSUpdateRRRecords,
				int16 wZones )
{
	int32 dwError = 0;
	int32 i = 0;
	DNS_RR_RECORD *pDNSUpdateRRRecord = NULL;

	for ( i = 0; i < wZones; i++ ) {

		pDNSUpdateRRRecord = *( ppDNSUpdateRRRecords + i );

		dwError =
			DNSMarshallRRHeader( hSendBuffer,
					     pDNSUpdateRRRecord );

		if ( pDNSUpdateRRRecord->RRHeader.wRDataSize ) {
			dwError = DNSMarshallRData( hSendBuffer,
						    pDNSUpdateRRRecord );
			BAIL_ON_ERROR( dwError );
		}

	}
      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

static int32 DNSUpdateMarshallAdditionalSection( HANDLE hSendBuffer,
				    DNS_RR_RECORD **
				    ppDNSAdditionalsRRRecords,
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

		if ( pDNSAdditionalRRRecord->RRHeader.wRDataSize ) {
			dwError = DNSMarshallRData( hSendBuffer,
						    pDNSAdditionalRRRecord );
			BAIL_ON_ERROR( dwError );
		}
	}

      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSUpdateSendUpdateRequest2( HANDLE hDNSServer,
			     DNS_UPDATE_REQUEST * pDNSRequest )
{
	int32 dwError = 0;
	int32 dwBytesSent = 0;
	HANDLE hSendBuffer = ( HANDLE ) NULL;

	dwError = DNSUpdateBuildRequestMessage( pDNSRequest, &hSendBuffer );
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

int32 DNSUpdateBuildRequestMessage( DNS_UPDATE_REQUEST * pDNSRequest,
			      HANDLE * phSendBuffer )
{
	int32 dwError = 0;
	char DNSMessageHeader[12];
	int16 wnIdentification = 0;
	int16 wnParameter = 0;
	int16 wnZones = 0;
	int16 wnPRs = 0;
	int16 wnUpdates = 0;
	int16 wnAdditionals = 0;
	int32 dwRead = 0;
	HANDLE hSendBuffer = ( HANDLE ) NULL;

	dwError = DNSCreateSendBuffer( &hSendBuffer );
	BAIL_ON_ERROR( dwError );

	wnIdentification = htons( pDNSRequest->wIdentification );
	memcpy( DNSMessageHeader, ( char * ) &wnIdentification, 2 );

	wnParameter = htons( pDNSRequest->wParameter );
	memcpy( DNSMessageHeader + 2, ( char * ) &wnParameter, 2 );

	wnZones = htons( pDNSRequest->wZones );
	memcpy( DNSMessageHeader + 4, ( char * ) &wnZones, 2 );

	wnPRs = htons( pDNSRequest->wPRs );
	memcpy( DNSMessageHeader + 6, ( char * ) &wnPRs, 2 );

	wnUpdates = htons( pDNSRequest->wUpdates );
	memcpy( DNSMessageHeader + 8, ( char * ) &wnUpdates, 2 );

	wnAdditionals = htons( pDNSRequest->wAdditionals );
	memcpy( DNSMessageHeader + 10, ( char * ) &wnAdditionals, 2 );

	dwError =
		DNSMarshallBuffer( hSendBuffer, ( uint8 * ) DNSMessageHeader,
				   12, &dwRead );
	BAIL_ON_ERROR( dwError );

	if ( pDNSRequest->wZones ) {
		dwError =
			DNSUpdateMarshallZoneSection( hSendBuffer,
						      pDNSRequest->
						      ppZoneRRSet,
						      pDNSRequest->wZones );
		BAIL_ON_ERROR( dwError );
	}

	if ( pDNSRequest->wPRs ) {
		dwError =
			DNSUpdateMarshallPRSection( hSendBuffer,
						    pDNSRequest->ppPRRRSet,
						    pDNSRequest->wPRs );
		BAIL_ON_ERROR( dwError );
	}

	if ( pDNSRequest->wUpdates ) {
		dwError =
			DNSUpdateMarshallUpdateSection( hSendBuffer,
							pDNSRequest->
							ppUpdateRRSet,
							pDNSRequest->
							wUpdates );
		BAIL_ON_ERROR( dwError );
	}

	if ( pDNSRequest->wAdditionals ) {
		dwError =
			DNSUpdateMarshallAdditionalSection( hSendBuffer,
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

void DNSUpdateFreeRequest( DNS_UPDATE_REQUEST * pDNSRequest )
{
	return;
}

/*********************************************************************
*********************************************************************/

int32 DNSUpdateAddZoneSection( DNS_UPDATE_REQUEST * pDNSRequest,
			 DNS_ZONE_RECORD * pDNSZone )
{
	int32 dwNumZones = 0;
	int32 dwError = 0;

	dwNumZones = pDNSRequest->wZones;

	dwError = DNSReallocMemory( ( uint8 * ) pDNSRequest->ppZoneRRSet,
				    ( void * ) &pDNSRequest->ppZoneRRSet,
				    ( dwNumZones +
				      1 ) * sizeof( DNS_ZONE_RECORD * )
		 );
	BAIL_ON_ERROR( dwError );

	*( pDNSRequest->ppZoneRRSet + dwNumZones ) = pDNSZone;

	pDNSRequest->wZones += 1;

      error:

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSUpdateAddAdditionalSection( DNS_UPDATE_REQUEST * pDNSRequest,
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

int32 DNSUpdateAddPRSection( DNS_UPDATE_REQUEST * pDNSRequest,
		       DNS_RR_RECORD * pDNSRecord )
{
	int32 dwNumPRs = 0;
	int32 dwError = 0;

	dwNumPRs = pDNSRequest->wPRs;
	dwError = DNSReallocMemory( pDNSRequest->ppPRRRSet,
				    ( void * ) &pDNSRequest->ppPRRRSet,
				    ( dwNumPRs +
				      1 ) * sizeof( DNS_RR_RECORD * ) );
	BAIL_ON_ERROR( dwError );

	*( pDNSRequest->ppPRRRSet + dwNumPRs ) = pDNSRecord;

	pDNSRequest->wPRs += 1;

      error:
	return dwError;
}


/*********************************************************************
*********************************************************************/

int32 DNSUpdateAddUpdateSection( DNS_UPDATE_REQUEST * pDNSRequest,
			   DNS_RR_RECORD * pDNSRecord )
{
	int32 dwError = 0;
	int16 wNumUpdates = 0;

	wNumUpdates = pDNSRequest->wUpdates;
	dwError = DNSReallocMemory( pDNSRequest->ppUpdateRRSet,
				    ( void * ) &pDNSRequest->ppUpdateRRSet,
				    ( wNumUpdates +
				      1 ) * sizeof( DNS_RR_RECORD * ) );
	BAIL_ON_ERROR( dwError );

	*( pDNSRequest->ppUpdateRRSet + wNumUpdates ) = pDNSRecord;

	pDNSRequest->wUpdates += 1;

      error:
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSUpdateCreateUpdateRequest( DNS_UPDATE_REQUEST ** ppDNSRequest )
{
	int32 dwError = 0;
	DNS_UPDATE_REQUEST *pDNSRequest = NULL;

	dwError =
		DNSAllocateMemory( sizeof( DNS_UPDATE_REQUEST ),
				   ( void * ) &pDNSRequest );
	BAIL_ON_ERROR( dwError );

	dwError = DNSGenerateIdentifier( &pDNSRequest->wIdentification );
	BAIL_ON_ERROR( dwError );

	pDNSRequest->wParameter = 0x2800;

	*ppDNSRequest = pDNSRequest;

	return dwError;

      error:

	if ( pDNSRequest ) {
		DNSUpdateFreeRequest( pDNSRequest );
	}
	*ppDNSRequest = NULL;
	return dwError;
}
