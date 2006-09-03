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

int32 DNSCreateDeleteRecord( char *szHost, int16 wClass,
			     int16 wType, DNS_RR_RECORD ** ppDNSRecord )
{
	int32 dwError = 0;
	DNS_RR_RECORD *pDNSRRRecord = NULL;
	DNS_DOMAIN_NAME *pDomainName = NULL;

	dwError = DNSDomainNameFromString( szHost, &pDomainName );
	BAIL_ON_ERROR( dwError );

	dwError = DNSAllocateMemory( sizeof( DNS_RR_RECORD ),
				     ( void * ) &pDNSRRRecord );
	BAIL_ON_ERROR( dwError );

	pDNSRRRecord->RRHeader.dwTTL = 0;
	pDNSRRRecord->RRHeader.wClass = wClass;
	pDNSRRRecord->RRHeader.wType = wType;
	pDNSRRRecord->RRHeader.pDomainName = pDomainName;
	pDNSRRRecord->RRHeader.wRDataSize = 0;

	*ppDNSRecord = pDNSRRRecord;

	return dwError;
      error:

	if ( pDomainName ) {
		DNSFreeDomainName( pDomainName );
	}
	if ( pDNSRRRecord ) {
		DNSFreeMemory( pDNSRRRecord );
	}

	*ppDNSRecord = NULL;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSCreateARecord( char *szHost, int16 wClass,
		  int16 wType, int32 dwIP, DNS_RR_RECORD ** ppDNSRecord )
{
	int32 dwError = 0;
	DNS_RR_RECORD *pDNSRRRecord = NULL;
	DNS_DOMAIN_NAME *pDomainName = NULL;
	uint8 *pRData = NULL;
	int32 dwnIP = 0;

	dwError = DNSDomainNameFromString( szHost, &pDomainName );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSAllocateMemory( sizeof( DNS_RR_RECORD ),
				   ( void * ) &pDNSRRRecord );
	BAIL_ON_ERROR( dwError );

	pDNSRRRecord->RRHeader.wType = wType;
	pDNSRRRecord->RRHeader.pDomainName = pDomainName;

	pDNSRRRecord->RRHeader.wClass = wClass;
	pDNSRRRecord->RRHeader.wRDataSize = 0;
	pDNSRRRecord->RRHeader.dwTTL = 0;

	if ( wClass != DNS_CLASS_ANY ) {
		pDNSRRRecord->RRHeader.dwTTL = DNS_ONE_DAY_IN_SECS;
		pDNSRRRecord->RRHeader.wRDataSize = sizeof( int32 );
		dwError =
			DNSAllocateMemory( sizeof( int32 ),
					   ( void * ) &pRData );
		dwnIP = htonl( dwIP );
		memcpy( pRData, &dwnIP, sizeof( int32 ) );
		pDNSRRRecord->pRData = pRData;
	}

	*ppDNSRecord = pDNSRRRecord;

	return dwError;
      error:

	if ( pDomainName ) {
		DNSFreeDomainName( pDomainName );
	}
	if ( pDNSRRRecord ) {
		DNSFreeMemory( pDNSRRRecord );
	}

	if ( pDNSRRRecord ) {
		DNSFreeMemory( pRData );
	}
	*ppDNSRecord = NULL;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSCreateTKeyRecord( char *szKeyName, uint8 * pKeyData,
		     int16 wKeySize, DNS_RR_RECORD ** ppDNSRecord )
{
	int32 dwError = 0;
	DNS_RR_RECORD *pDNSRecord = NULL;
	DNS_DOMAIN_NAME *pAlgorithmName = NULL;
	DNS_DOMAIN_NAME *pDomainName = NULL;
	time_t t;

	int32 dwRDataSize = 0;
	int32 dwnInception, dwInception = 0;
	int32 dwnExpiration, dwExpiration = 0;
	int16 wnMode, wMode = 0;
	int16 wnError, wError = 0;
	int16 wnKeySize = 0;
	int16 wnOtherSize, wOtherSize = 0;

	int32 dwAlgorithmLen = 0;
	int32 dwCopied = 0;
	int32 dwOffset = 0;

	uint8 *pRData = NULL;

	char szTemp[20];

	dwError =
		DNSAllocateMemory( sizeof( DNS_RR_RECORD ),
				   ( void * ) &pDNSRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSDomainNameFromString( szKeyName, &pDomainName );
	BAIL_ON_ERROR( dwError );

	strncpy( szTemp, "gss.microsoft.com", sizeof( szTemp ) );
	dwError = DNSDomainNameFromString( szTemp, &pAlgorithmName );
	BAIL_ON_ERROR( dwError );

	pDNSRecord->RRHeader.dwTTL = 0;
	pDNSRecord->RRHeader.pDomainName = pDomainName;
	pDNSRecord->RRHeader.wClass = DNS_CLASS_ANY;
	pDNSRecord->RRHeader.wType = QTYPE_TKEY;

	time( &t );
	dwExpiration = ( int32 ) t + DNS_ONE_DAY_IN_SECS;
	dwInception = ( int32 ) t;
	wError = 0;
	wMode = 3;

	dwError = DNSGetDomainNameLength( pAlgorithmName, &dwAlgorithmLen );
	BAIL_ON_ERROR( dwError );

	dwRDataSize = dwAlgorithmLen +
		sizeof( dwExpiration ) + sizeof( dwInception ) +
		sizeof( wError ) + sizeof( wMode ) + +sizeof( wError ) +
		sizeof( wKeySize ) + wKeySize + sizeof( wOtherSize ) +
		wOtherSize;

	dwError = DNSAllocateMemory( dwRDataSize, ( void * ) &pRData );
	BAIL_ON_ERROR( dwError );

	dwnInception = htonl( dwInception );
	dwnExpiration = htonl( dwExpiration );
	wnMode = htons( wMode );
	wnError = htons( wError );
	wnKeySize = htons( wKeySize );
	wnOtherSize = htons( wOtherSize );

	dwError = DNSCopyDomainName( pRData, pAlgorithmName, &dwCopied );
	BAIL_ON_ERROR( dwError );
	dwOffset += dwCopied;

	memcpy( pRData + dwOffset, &dwnInception, sizeof( int32 ) );
	dwOffset += sizeof( int32 );

	memcpy( pRData + dwOffset, &dwnExpiration, sizeof( int32 ) );
	dwOffset += sizeof( int32 );

	memcpy( pRData + dwOffset, &wnMode, sizeof( int16 ) );
	dwOffset += sizeof( int16 );

	memcpy( pRData + dwOffset, &wnError, sizeof( int16 ) );
	dwOffset += sizeof( int16 );

	memcpy( pRData + dwOffset, &wnKeySize, sizeof( int16 ) );
	dwOffset += sizeof( int16 );

	memcpy( pRData + dwOffset, pKeyData, wKeySize );
	dwOffset += wKeySize;

	memcpy( pRData + dwOffset, &wnOtherSize, sizeof( int16 ) );
	dwOffset += sizeof( int16 );

	pDNSRecord->RRHeader.wRDataSize = ( int16 ) dwRDataSize;

	pDNSRecord->pRData = pRData;
	*ppDNSRecord = pDNSRecord;

	return dwError;

      error:


	if ( pDNSRecord ) {
		DNSFreeMemory( pDNSRecord );
	}

	if ( pDomainName ) {
		DNSFreeDomainName( pDomainName );
	}

	if ( pAlgorithmName ) {
		DNSFreeDomainName( pAlgorithmName );
	}

	*ppDNSRecord = NULL;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSCreateTSIGRecord( char *szKeyName, int32 dwTimeSigned,
		     int16 wFudge, int16 wOriginalID, uint8 * pMac,
		     int16 wMacSize, DNS_RR_RECORD ** ppDNSRecord )
{
	int32 dwError = 0;
	DNS_RR_RECORD *pDNSRecord = NULL;
	DNS_DOMAIN_NAME *pAlgorithmName = NULL;
	DNS_DOMAIN_NAME *pDomainName = NULL;
	time_t t;

	int32 dwRDataSize = 0;

	int16 wnFudge = 0;
	int16 wnError = 0, wError = 0;
	int16 wnMacSize = 0;
	int16 wnOriginalID = 0;
	int16 wnOtherLen = 0, wOtherLen = 0;

	int32 dwAlgorithmLen = 0;
	int32 dwCopied = 0;
	int32 dwOffset = 0;

	uint8 *pRData = NULL;

	int32 dwnTimeSigned = 0;
	int16 wnTimePrefix = 0;
	int16 wTimePrefix = 0;

	char szTemp[20];

	dwError =
		DNSAllocateMemory( sizeof( DNS_RR_RECORD ),
				   ( void * ) &pDNSRecord );
	BAIL_ON_ERROR( dwError );

	dwError = DNSDomainNameFromString( szKeyName, &pDomainName );
	BAIL_ON_ERROR( dwError );

	strncpy( szTemp, "gss.microsoft.com", sizeof( szTemp ) );
	dwError = DNSDomainNameFromString( szTemp, &pAlgorithmName );
	BAIL_ON_ERROR( dwError );

	pDNSRecord->RRHeader.dwTTL = 0;
	pDNSRecord->RRHeader.pDomainName = pDomainName;
	pDNSRecord->RRHeader.wClass = DNS_CLASS_ANY;
	pDNSRecord->RRHeader.wType = QTYPE_TSIG;

	/* This needs to be a 48bit value - 6 octets. */

	time( &t );

	dwError = DNSGetDomainNameLength( pAlgorithmName, &dwAlgorithmLen );
	BAIL_ON_ERROR( dwError );

	dwRDataSize = dwAlgorithmLen + 6 + sizeof( wFudge ) + sizeof( wMacSize ) +
		wMacSize + sizeof( wOriginalID ) + sizeof( wError ) +
		sizeof( wOtherLen );

	dwError = DNSAllocateMemory( dwRDataSize, ( void * ) &pRData );
	BAIL_ON_ERROR( dwError );

	/* Convert t to 48 bit network order */

	wnTimePrefix = htons( wTimePrefix );
	dwnTimeSigned = htonl( dwTimeSigned );
	wnFudge = htons( wFudge );
	wnMacSize = htons( wMacSize );
	wnOriginalID = htons( wOriginalID );
	wnError = htons( wError );
	wnOtherLen = htons( wOtherLen );

	dwError = DNSCopyDomainName( pRData, pAlgorithmName, &dwCopied );
	BAIL_ON_ERROR( dwError );
	dwOffset += dwCopied;

	memcpy( pRData + dwOffset, &wnTimePrefix, sizeof( int16 ) );
	dwOffset += sizeof( int16 );

	memcpy( pRData + dwOffset, &dwnTimeSigned, sizeof( int32 ) );
	dwOffset += sizeof( int32 );

	memcpy( pRData + dwOffset, &wnFudge, sizeof( int16 ) );
	dwOffset += sizeof( int16 );


	memcpy( pRData + dwOffset, &wnMacSize, sizeof( int16 ) );
	dwOffset += sizeof( int16 );

	memcpy( pRData + dwOffset, pMac, wMacSize );
	dwOffset += wMacSize;

	memcpy( pRData + dwOffset, &wnOriginalID, sizeof( int16 ) );
	dwOffset += sizeof( int16 );

	memcpy( pRData + dwOffset, &wnError, sizeof( int16 ) );
	dwOffset += sizeof( int16 );

	memcpy( pRData + dwOffset, &wnOtherLen, sizeof( int16 ) );
	dwOffset += sizeof( int16 );

	pDNSRecord->RRHeader.wRDataSize = ( int16 ) dwRDataSize;

	pDNSRecord->pRData = pRData;
	*ppDNSRecord = pDNSRecord;

	return dwError;

      error:


	if ( pDNSRecord ) {
		DNSFreeMemory( pDNSRecord );
	}

	if ( pDomainName ) {
		DNSFreeDomainName( pDomainName );
	}

	if ( pAlgorithmName ) {
		DNSFreeDomainName( pAlgorithmName );
	}

	*ppDNSRecord = NULL;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSCreateQuestionRecord( char *pszQName, int16 wQType,
                               int16 wQClass,
                               DNS_QUESTION_RECORD ** ppDNSQuestionRecord )
{
	int32 dwError = 0;
	DNS_QUESTION_RECORD *pDNSQuestionRecord = NULL;
	DNS_DOMAIN_NAME *pDomainName = NULL;

	dwError = DNSDomainNameFromString( pszQName, &pDomainName );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSAllocateMemory( sizeof( DNS_QUESTION_RECORD ),
				   ( void * ) &pDNSQuestionRecord );
	BAIL_ON_ERROR( dwError );

	pDNSQuestionRecord->pDomainName = pDomainName;
	pDNSQuestionRecord->wQueryClass = wQClass;
	pDNSQuestionRecord->wQueryType = wQType;

	*ppDNSQuestionRecord = pDNSQuestionRecord;

	return dwError;
      error:

	if ( pDomainName ) {
		DNSFreeDomainName( pDomainName );
	}
	if ( pDNSQuestionRecord ) {
		DNSFreeMemory( pDNSQuestionRecord );
	}
	*ppDNSQuestionRecord = NULL;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSCreateZoneRecord( const char *pszZName, DNS_ZONE_RECORD ** ppDNSZoneRecord )
{
	int32 dwError = 0;
	DNS_ZONE_RECORD *pDNSZoneRecord = NULL;
	DNS_DOMAIN_NAME *pDomainName = NULL;

	dwError = DNSDomainNameFromString( pszZName, &pDomainName );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSAllocateMemory( sizeof( DNS_ZONE_RECORD ),
				   ( void * ) &pDNSZoneRecord );
	BAIL_ON_ERROR( dwError );

	pDNSZoneRecord->pDomainName = pDomainName;
	pDNSZoneRecord->wZoneClass = DNS_CLASS_IN;
	pDNSZoneRecord->wZoneType = QTYPE_SOA;

	*ppDNSZoneRecord = pDNSZoneRecord;

	return dwError;
      error:

	if ( pDomainName ) {
		DNSFreeDomainName( pDomainName );
	}
	if ( pDNSZoneRecord ) {
		DNSFreeMemory( pDNSZoneRecord );
	}
	*ppDNSZoneRecord = NULL;
	return dwError;
}

int32 DNSFreeZoneRecord( DNS_ZONE_RECORD * pDNSZoneRecord )
{
	int32 dwError = 0;

	return dwError;

}

/*********************************************************************
*********************************************************************/

int32 DNSCreateNameInUseRecord( char *pszName, int32 qtype,
				struct in_addr * ip,
				DNS_RR_RECORD * *ppDNSRRRecord )
{
	int32 dwError = 0;
	DNS_RR_RECORD *pDNSRRRecord = NULL;
	DNS_DOMAIN_NAME *pDomainName = NULL;

	dwError = DNSDomainNameFromString( pszName, &pDomainName );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSAllocateMemory( sizeof( DNS_RR_RECORD ),
				   ( void * ) &pDNSRRRecord );
	BAIL_ON_ERROR( dwError );

	pDNSRRRecord->RRHeader.pDomainName = pDomainName;
	pDNSRRRecord->RRHeader.dwTTL = 0;
	pDNSRRRecord->RRHeader.wType = qtype;

	if ( !ip ) {
		pDNSRRRecord->RRHeader.wClass = DNS_CLASS_ANY;
		pDNSRRRecord->RRHeader.wRDataSize = 0;
	} else {
		pDNSRRRecord->RRHeader.wClass = DNS_CLASS_IN;
		pDNSRRRecord->RRHeader.wRDataSize = 4;
		dwError =
			DNSAllocateMemory( 4,
					   ( void * ) &pDNSRRRecord->
					   pRData );
		BAIL_ON_ERROR( dwError );
		memcpy( pDNSRRRecord->pRData, &ip->s_addr, 4 );
	}

	*ppDNSRRRecord = pDNSRRRecord;

	return dwError;
      error:

	if ( pDomainName ) {
		DNSFreeDomainName( pDomainName );
	}
	if ( pDNSRRRecord ) {
		DNSFreeMemory( pDNSRRRecord );
	}
	*ppDNSRRRecord = NULL;

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSCreateNameNotInUseRecord( char *pszName, int32 qtype,
				   DNS_RR_RECORD * *ppDNSRRRecord )
{
	int32 dwError = 0;
	DNS_RR_RECORD *pDNSRRRecord = NULL;
	DNS_DOMAIN_NAME *pDomainName = NULL;

	dwError = DNSDomainNameFromString( pszName, &pDomainName );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSAllocateMemory( sizeof( DNS_RR_RECORD ),
				   ( void * ) &pDNSRRRecord );
	BAIL_ON_ERROR( dwError );

	pDNSRRRecord->RRHeader.pDomainName = pDomainName;
	pDNSRRRecord->RRHeader.wClass = DNS_CLASS_NONE;
	pDNSRRRecord->RRHeader.wType = qtype;
	pDNSRRRecord->RRHeader.dwTTL = 0;
	pDNSRRRecord->RRHeader.wRDataSize = 0;

	*ppDNSRRRecord = pDNSRRRecord;

	return dwError;
      error:

	if ( pDomainName ) {
		DNSFreeDomainName( pDomainName );
	}
	if ( pDNSRRRecord ) {
		DNSFreeMemory( pDNSRRRecord );
	}
	*ppDNSRRRecord = NULL;
	return dwError;

}

