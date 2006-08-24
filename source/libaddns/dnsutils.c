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
#include <ctype.h>

#define TRUE 		1
#define FALSE		0

#define STATE_BEGIN  0
#define STATE_LABEL  1
#define STATE_FINISH 2

#define TOKEN_LABEL		1
#define TOKEN_SEPARATOR		2
#define TOKEN_EOS 		3

/*********************************************************************
*********************************************************************/

static int32 getToken( char *pszString, char *pszToken, int32 * pdwToken, 
                       int32 * pdwPosition )
{
	int32 dwError = 0;
	char c = 0;
	int32 dwToken = 0;
	int32 i = 0;
	int32 dwState = 0;
	int32 dwPosition = 0;

	dwPosition = *pdwPosition;
	dwState = STATE_BEGIN;
	while ( dwState != STATE_FINISH ) {
		c = pszString[dwPosition];
		if ( c == '\0' ) {
			if ( dwState == STATE_LABEL ) {
				dwToken = TOKEN_LABEL;
				dwState = STATE_FINISH;
				continue;
			} else if ( dwState == STATE_BEGIN ) {
				dwToken = TOKEN_EOS;
				dwState = STATE_FINISH;
				continue;
			}
		} else if ( isalnum( c ) || c == '-' ) {
			pszToken[i++] = c;
			dwPosition++;
			dwState = STATE_LABEL;
			continue;
		} else if ( c == '.' ) {
			if ( dwState == STATE_LABEL ) {
				dwToken = TOKEN_LABEL;
				dwState = STATE_FINISH;
				continue;
			} else if ( dwState == STATE_BEGIN ) {
				dwToken = TOKEN_SEPARATOR;
				dwPosition++;
				dwState = STATE_FINISH;
				continue;
			}
		} else {
			if ( dwState == STATE_LABEL ) {
				dwToken = TOKEN_LABEL;
				dwState = STATE_FINISH;
			} else if ( dwState == 0 ) {
				dwError = ERROR_INVALID_PARAMETER;
				dwState = STATE_FINISH;
			}
		}
	}
	*pdwPosition = dwPosition;
	*pdwToken = dwToken;
	return dwError;
}

/*********************************************************************
*********************************************************************/

static int32 DNSMakeLabel( char *szLabel, DNS_DOMAIN_LABEL ** ppLabel )
{
	DNS_DOMAIN_LABEL *pLabel = NULL;
	char *pszLabel = NULL;
	int32 dwError = 0;

	dwError =
		DNSAllocateMemory( sizeof( DNS_DOMAIN_LABEL ),
				   ( void * ) &pLabel );
	BAIL_ON_ERROR( dwError );

	dwError = DNSAllocateString( szLabel, &pszLabel );
	BAIL_ON_ERROR( dwError );

	pLabel->pszLabel = pszLabel;
	pLabel->dwLength = ( int32 ) strlen( pszLabel );
	*ppLabel = pLabel;
	return dwError;

      error:

	if ( pLabel ) {
		DNSFreeMemory( pLabel );
	}
	*ppLabel = NULL;
	return dwError;
}

/*********************************************************************
*********************************************************************/

static void DNSFreeLabel( DNS_DOMAIN_LABEL * pLabel )
{
	if ( pLabel ) {
		DNSFreeMemory( pLabel );
	}
	return;
}

/*********************************************************************
*********************************************************************/

void DNSFreeLabelList(DNS_DOMAIN_LABEL *pLabelList)
{
	DNS_DOMAIN_LABEL *pTemp = NULL;
	while(pLabelList) {
		pTemp = pLabelList;
		pLabelList = pLabelList->pNext;
		DNSFreeLabel(pTemp);
	}
	
	return;
}

/*********************************************************************
*********************************************************************/

void DNSFreeDomainName(DNS_DOMAIN_NAME *pDomainName)
{
	DNSFreeLabelList(pDomainName->pLabelList);
	DNSFreeMemory(pDomainName);
	
	return;
}

/*********************************************************************
*********************************************************************/

static int32 LabelList( char *pszString, int32 * pdwPosition, DNS_DOMAIN_LABEL ** ppList )
{
	int32 dwError = 0;
	DNS_DOMAIN_LABEL *pList = NULL;
	DNS_DOMAIN_LABEL *pLabel = NULL;
	int32 dwToken = 0;
	char szToken[64];

	memset( szToken, 0, 64 );
	dwError = getToken( pszString, szToken, &dwToken, pdwPosition );
	BAIL_ON_ERROR( dwError );
	if ( dwToken != TOKEN_LABEL ) {
		dwError = ERROR_INVALID_PARAMETER;
		BAIL_ON_ERROR( dwError );
	}

	dwError = DNSMakeLabel( szToken, &pLabel );
	BAIL_ON_ERROR( dwError );

	memset( szToken, 0, 64 );
	dwError = getToken( pszString, szToken, &dwToken, pdwPosition );
	BAIL_ON_ERROR( dwError );
	if ( dwToken == TOKEN_EOS ) {
		*ppList = pLabel;
		return dwError;
	} else if ( dwToken == TOKEN_SEPARATOR ) {
		dwError = LabelList( pszString, pdwPosition, &pList );
		BAIL_ON_ERROR( dwError );

		pLabel->pNext = pList;
		*ppList = pLabel;
	}

	return dwError;

      error:
	if ( pLabel ) {
		DNSFreeLabel( pLabel );
	}

	return dwError;
}

/*********************************************************************
*********************************************************************/

static int32 DNSGetDomainNameOffset( uint8 * pBuffer )
{
	uint8 uLen = 0;
	uint8 uLen1;
	int32 dwOffset = 0;

	uLen1 = *pBuffer;
	if ( uLen1 & 0xC0 ) {
		dwOffset += 2;

	} else {

		while ( 1 ) {

			uLen = *pBuffer;
			pBuffer++;
			dwOffset++;
			if ( uLen == 0 ) {
				break;
			}
			dwOffset += uLen;
			pBuffer += uLen;
		}
	}
	return ( dwOffset );
}

/*********************************************************************
*********************************************************************/

int32 DNSGenerateIdentifier( int16 * pwIdentifier )
{
	int32 dwError = 0;

	*pwIdentifier = random(  );

	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSGetDomainNameLength( DNS_DOMAIN_NAME * pDomainName, int32 * pdwLength )
{
	int32 dwError = 0;
	int32 dwLength = 0;
	DNS_DOMAIN_LABEL *pDomainLabel = NULL;

	if ( !pDomainName ) {
		dwError = ERROR_INVALID_PARAMETER;
		BAIL_ON_ERROR( dwError );
	}
	pDomainLabel = pDomainName->pLabelList;

	while ( pDomainLabel ) {
		dwLength += pDomainLabel->dwLength;
		dwLength += 1;
		pDomainLabel = pDomainLabel->pNext;
	}
	dwLength += 1;
	*pdwLength = dwLength;

	return dwError;
      error:

	*pdwLength = 0;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSCopyDomainName( uint8 * pBuffer,
		   DNS_DOMAIN_NAME * pDomainName, int32 * pdwCopied )
{
	int32 dwError = 0;
	DNS_DOMAIN_LABEL *pDomainLabel = NULL;
	uint8 uChar = 0;
	int32 dwCopied = 0;

	if ( !pDomainName ) {
		dwError = ERROR_INVALID_PARAMETER;
		BAIL_ON_ERROR( dwError );
	}

	pDomainLabel = pDomainName->pLabelList;
	while ( pDomainLabel ) {
		uChar = ( uint8 ) pDomainLabel->dwLength;
		memcpy( pBuffer + dwCopied, &uChar, sizeof( uint8 ) );
		dwCopied += sizeof( uint8 );
		memcpy( pBuffer + dwCopied, pDomainLabel->pszLabel,
			pDomainLabel->dwLength );
		dwCopied += pDomainLabel->dwLength;
		pDomainLabel = pDomainLabel->pNext;
	}
	uChar = 0;
	memcpy( pBuffer + dwCopied, &uChar, sizeof( uint8 ) );
	dwCopied += sizeof( uint8 );

	*pdwCopied = dwCopied;
	return dwError;

      error:
	*pdwCopied = 0;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSGenerateKeyName( char **ppszKeyName )
{
	int32 dwError = 0;
#if defined(WITH_DNS_UPDATES)
	char *pszKeyName = NULL;
	char szTemp[256];
	char szBuffer[256];
	unsigned char uuid[16];

	memset( szTemp, 0, 256 );
	memset( szBuffer, 0, 256 );
	memset( uuid, 0, 16 );

	uuid_generate( uuid );

	uuid_unparse( uuid, szBuffer );

	strcpy( szTemp, szBuffer );
	dwError = DNSAllocateString( szTemp, &pszKeyName );
	BAIL_ON_ERROR( dwError );

	*ppszKeyName = pszKeyName;

	return dwError;

      error:
#endif

	*ppszKeyName = NULL;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 DNSDomainNameFromString( char *pszDomainName,
			 DNS_DOMAIN_NAME ** ppDomainName )
{
	int32 dwError = 0;
	int32 dwPosition = 0;
	DNS_DOMAIN_NAME *pDomainName = NULL;
	DNS_DOMAIN_LABEL *pLabelList = NULL;

	if ( !pszDomainName || !*pszDomainName ) {
		dwError = ERROR_INVALID_PARAMETER;
		return dwError;
	}

	dwError = LabelList( pszDomainName, &dwPosition, &pLabelList );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSAllocateMemory( sizeof( DNS_DOMAIN_NAME ),
				   ( void * ) &pDomainName );
	BAIL_ON_ERROR( dwError );

	pDomainName->pLabelList = pLabelList;

	*ppDomainName = pDomainName;

	return dwError;

      error:

	if ( pLabelList ) {
		DNSFreeLabelList( pLabelList );
	}
	*ppDomainName = NULL;

	return dwError;
}


/*********************************************************************
*********************************************************************/

int32 DNSAppendLabel( DNS_DOMAIN_LABEL * pLabelList,
                     DNS_DOMAIN_LABEL * pLabel,
                     DNS_DOMAIN_LABEL ** ppNewLabelList )
{
	DNS_DOMAIN_LABEL **ppLabelList = NULL;
	int32 dwError = 0;

	if ( pLabelList == NULL ) {
		*ppNewLabelList = pLabel;
		return dwError;
	}

	ppLabelList = &pLabelList;

	while ( ( *ppLabelList )->pNext ) {
		ppLabelList = &( ( *ppLabelList )->pNext );
	}

	( *ppLabelList )->pNext = pLabel;
	*ppNewLabelList = pLabelList;
	return dwError;
}

/*********************************************************************
*********************************************************************/

int32 GetLastError(  )
{
	return ( errno );
}

/*********************************************************************
*********************************************************************/

int32 WSAGetLastError( void )
{
	return ( errno );
}

/*********************************************************************
*********************************************************************/

void DNSRecordGenerateOffsets( DNS_RR_RECORD * pDNSRecord )
{
	int32 dwOffset = 0;
	uint8 *pRData = NULL;
	int16 wKeySize, wnKeySize = 0;

	pRData = pDNSRecord->pRData;
	switch ( pDNSRecord->RRHeader.wType ) {
	case QTYPE_TKEY:
		pDNSRecord->Offsets.TKey.wAlgorithmOffset =
			( int16 ) dwOffset;
		dwOffset += DNSGetDomainNameOffset( pRData );
		pDNSRecord->Offsets.TKey.wInceptionOffset =
			( int16 ) dwOffset;
		dwOffset += sizeof( int32 );
		pDNSRecord->Offsets.TKey.wExpirationOffset =
			( int16 ) dwOffset;
		dwOffset += sizeof( int32 );
		pDNSRecord->Offsets.TKey.wModeOffset = ( int16 ) dwOffset;
		dwOffset += sizeof( int16 );
		pDNSRecord->Offsets.TKey.wErrorOffset = ( int16 ) dwOffset;
		dwOffset += sizeof( int16 );
		pDNSRecord->Offsets.TKey.wKeySizeOffset = ( int16 ) dwOffset;
		dwOffset += sizeof( int16 );
		pDNSRecord->Offsets.TKey.wKeyDataOffset = ( int16 ) dwOffset;

		memcpy( &wnKeySize,
			pRData + pDNSRecord->Offsets.TKey.wKeySizeOffset,
			sizeof( int16 ) );
		wKeySize = ntohs( wnKeySize );

		dwOffset += wKeySize;
		pDNSRecord->Offsets.TKey.wOtherSizeOffset =
			( int16 ) dwOffset;
		dwOffset += sizeof( int16 );
		pDNSRecord->Offsets.TKey.wOtherDataOffset =
			( int16 ) dwOffset;
		break;

	case QTYPE_TSIG:
		break;
	}
	return;
}

/*********************************************************************
*********************************************************************/

int32 MapDNSResponseCodes( int16 wResponseCode )
{
	int16 wnResponseCode = 0;
	uint8 *pByte = NULL;

	wnResponseCode = htons( wResponseCode );
	pByte = ( uint8 * ) & wnResponseCode;

#if 0
	printf( "Byte 0 - %.2x\n", pByte[0] );
	printf( "Byte 1 - %.2x\n", pByte[1] );
#endif
	/* Bit 3, 2, 1, 0 of Byte 2 represent the RCode */

	return ( ( int32 ) pByte[1] );
}

/*********************************************************************
*********************************************************************/

int32 DNSAllocateMemory(int32 dwSize, void * _ppMemory)
{
	void **ppMemory = (void **)_ppMemory;
	int32 dwError = 0;
	void * pMemory = NULL;

	pMemory = malloc(dwSize);
	if (!pMemory){
		dwError = ERROR_OUTOFMEMORY;
		*ppMemory = NULL;
	}else {
		memset(pMemory,0, dwSize);
		*ppMemory = pMemory;
	}
	return (dwError);
}

/*********************************************************************
*********************************************************************/

int32 DNSReallocMemory(void *  pMemory, void * _ppNewMemory, int32 dwSize)
{
	void **ppNewMemory = (void **)_ppNewMemory;
	int32 dwError = 0;
	void * pNewMemory = NULL;

	if (pMemory == NULL) {
		pNewMemory = malloc(dwSize);
		memset(pNewMemory, 0, dwSize);
	}else {
		pNewMemory = realloc(pMemory, dwSize);
	}
	if (!pNewMemory){
		dwError = ERROR_OUTOFMEMORY;
		*ppNewMemory = NULL;
	}else {
		*ppNewMemory = pNewMemory;
	}

	return(dwError);
}

/*********************************************************************
*********************************************************************/

void DNSFreeMemory( void * pMemory )
{
	free(pMemory);
	return;
}

/*********************************************************************
*********************************************************************/

int32 DNSAllocateString(char *pszInputString, char **ppszOutputString)
{
	int32 dwError = 0;
	int32 dwLen = 0;
	char * pszOutputString = NULL;

	if (!pszInputString || !*pszInputString){
		dwError = ERROR_INVALID_PARAMETER;
		BAIL_ON_ERROR(dwError);
	}
	dwLen = (int32)strlen(pszInputString);
	dwError = DNSAllocateMemory(dwLen+1, (void *)&pszOutputString);
	BAIL_ON_ERROR(dwError);

	strcpy(pszOutputString, pszInputString);

	*ppszOutputString = pszOutputString;

	return(dwError);
error:
	*ppszOutputString = pszOutputString;
	return(dwError);
}

/*********************************************************************
*********************************************************************/

void DNSFreeString(char * pszString)
{
	return;
}



