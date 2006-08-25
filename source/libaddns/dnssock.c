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
#include <sys/time.h>

/********************************************************************
********************************************************************/

static DNS_ERROR DNSTCPOpen( char *nameserver, HANDLE * phDNSServer )
{
	DNS_ERROR dwError = ERROR_DNS_INVALID_PARAMETER;
	int sockServer;
	unsigned long ulAddress;
	struct hostent *pHost;
	struct sockaddr_in s_in;
	DNS_CONNECTION_CONTEXT *pDNSContext = NULL;

	if ( (pDNSContext = TALLOC_P( NULL, DNS_CONNECTION_CONTEXT )) == NULL ) {
		return ERROR_DNS_NO_MEMORY;
	}

	if ( (ulAddress = inet_addr( nameserver )) == INADDR_NONE ) {
		if ( (pHost = gethostbyname( nameserver )) == NULL ) {
			dwError = ERROR_DNS_INVALID_NAME_SERVER;
			BAIL_ON_DNS_ERROR( dwError );
		}
		memcpy( &ulAddress, pHost->h_addr, pHost->h_length );
	}

	if ( (sockServer = socket( PF_INET, SOCK_STREAM, 0 )) == INVALID_SOCKET ) {
		dwError = ERROR_DNS_NO_MEMORY;
		BAIL_ON_DNS_ERROR( dwError );
	}

	s_in.sin_family = AF_INET;
	s_in.sin_addr.s_addr = ulAddress;
	s_in.sin_port = htons( DNS_TCP_PORT );

	if ( (connect( sockServer, (struct sockaddr*)&s_in, sizeof( s_in ))) == SOCKET_ERROR ) {
		dwError = ERROR_DNS_CONNECTION_FAILED;
		BAIL_ON_DNS_ERROR( dwError );
	}
		
	pDNSContext->s = sockServer;
	pDNSContext->hType = DNS_TCP;

	*phDNSServer = ( HANDLE ) pDNSContext;

	dwError = ERROR_DNS_SUCCESS;

	return dwError;

error:
	TALLOC_FREE( pDNSContext );
	*phDNSServer = ( HANDLE ) NULL;

	return dwError;
}

/********************************************************************
********************************************************************/

static DNS_ERROR DNSUDPOpen( char *nameserver, HANDLE * phDNSServer )
{
	DNS_ERROR dwError = ERROR_DNS_INVALID_PARAMETER;
	int SendSocket;
	unsigned long ulAddress;
	struct hostent *pHost;
	struct sockaddr_in RecvAddr;
	DNS_CONNECTION_CONTEXT *pDNSContext = NULL;

	if ( (pDNSContext = TALLOC_P( NULL, DNS_CONNECTION_CONTEXT )) == NULL ) {
		return ERROR_DNS_NO_MEMORY;
	}

	if ( (ulAddress = inet_addr( nameserver )) == INADDR_NONE ) {
		if ( (pHost = gethostbyname( nameserver )) == NULL ) {
			dwError = ERROR_DNS_INVALID_NAME_SERVER;
			BAIL_ON_DNS_ERROR( dwError );
		}
		memcpy( &ulAddress, pHost->h_addr, pHost->h_length );
	}
	
	/* Create a socket for sending data */

	SendSocket = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );

	/* Set up the RecvAddr structure with the IP address of
	   the receiver (in this example case "123.456.789.1")
	   and the specified port number. */

	RecvAddr.sin_family = AF_INET;
	RecvAddr.sin_port = htons( DNS_UDP_PORT );
	RecvAddr.sin_addr.s_addr = ulAddress;

	pDNSContext->s = SendSocket;
	pDNSContext->hType = DNS_UDP;
	memcpy( &pDNSContext->RecvAddr, &RecvAddr, sizeof( struct sockaddr_in ) );

	*phDNSServer = ( HANDLE ) pDNSContext;

	dwError = ERROR_DNS_SUCCESS;

	return dwError;

error:
	TALLOC_FREE( pDNSContext );
	*phDNSServer = ( HANDLE ) NULL;

	return dwError;
}

/********************************************************************
********************************************************************/

DNS_ERROR DNSOpen( char *nameserver, int32 dwType, HANDLE * phDNSServer )
{
	switch ( dwType ) {
	case DNS_TCP:
		return DNSTCPOpen( nameserver, phDNSServer );
	case DNS_UDP:
		return DNSUDPOpen( nameserver, phDNSServer );
	}
	
	return ERROR_DNS_INVALID_PARAMETER;
}

/********************************************************************
********************************************************************/

static int32 DNSSendTCPRequest( HANDLE hDNSHandle,
		   uint8 * pDNSSendBuffer,
		   int32 dwBufferSize, int32 * pdwBytesSent )
{
	int32 dwError = 0;
	int32 dwBytesSent = 0;
	DNS_CONNECTION_CONTEXT *pDNSContext = NULL;


	pDNSContext = ( DNS_CONNECTION_CONTEXT * ) hDNSHandle;

	dwBytesSent = send( pDNSContext->s, pDNSSendBuffer, dwBufferSize, 0 );
	if ( dwBytesSent == SOCKET_ERROR ) {
		dwError = WSAGetLastError(  );
		BAIL_ON_ERROR( dwError );
	}

	*pdwBytesSent = dwBytesSent;

	return dwError;

      error:
	*pdwBytesSent = 0;
	return dwError;
}

/********************************************************************
********************************************************************/

static int32 DNSSendUDPRequest( HANDLE hDNSHandle,
		   uint8 * pDNSSendBuffer,
		   int32 dwBufferSize, int32 * pdwBytesSent )
{
	int32 dwError = 0;
	int32 dwBytesSent = 0;
	DNS_CONNECTION_CONTEXT *pDNSContext = NULL;

	pDNSContext = ( DNS_CONNECTION_CONTEXT * ) hDNSHandle;

	dwBytesSent = sendto( pDNSContext->s,
			      pDNSSendBuffer,
			      dwBufferSize,
			      0,
			      ( struct sockaddr * ) & pDNSContext->RecvAddr,
			      sizeof( pDNSContext->RecvAddr )
		 );
	if ( dwBytesSent == SOCKET_ERROR ) {
		dwError = WSAGetLastError(  );
		BAIL_ON_ERROR( dwError );
	} else {
		*pdwBytesSent = dwBytesSent;
	}

	return dwError;

      error:
	*pdwBytesSent = 0;
	return dwError;
}

/********************************************************************
********************************************************************/

static int32 DNSSelect( HANDLE hDNSHandle )
{
	int32 dwError = 0;
	fd_set rfds;
	struct timeval tv;
	int32 dwNumSockets = 0;
	DNS_CONNECTION_CONTEXT *pDNSContext = NULL;

	pDNSContext = ( DNS_CONNECTION_CONTEXT * ) hDNSHandle;
	FD_ZERO( &rfds );
	FD_SET( pDNSContext->s, &rfds );

	tv.tv_sec = 10;
	tv.tv_usec = 0;
	dwNumSockets = select( pDNSContext->s + 1, &rfds, NULL, NULL, &tv );
	if ( dwNumSockets == SOCKET_ERROR ) {
		dwError = WSAGetLastError(  );
		BAIL_ON_ERROR( dwError );
	}

	if ( !dwNumSockets ) {
#ifndef WIN32
		dwError = ETIMEDOUT;
#elif
		dwError = WSAETIMEDOUT;
#endif
	}

      error:

	return dwError;
}

/********************************************************************
********************************************************************/

static int32 DNSTCPReceiveBufferContext( HANDLE hDNSHandle,
			    HANDLE hDNSRecvBuffer, int32 * pdwBytesRead )
{
	int32 dwError = 0;
	int32 dwRead = 0;
	int16 wBytesToRead = 0;
	int16 wnBytesToRead = 0;
	DNS_CONNECTION_CONTEXT *pDNSContext = NULL;
	DNS_RECEIVEBUFFER_CONTEXT *pDNSRecvContext = NULL;

	pDNSContext = ( DNS_CONNECTION_CONTEXT * ) hDNSHandle;
	pDNSRecvContext = ( DNS_RECEIVEBUFFER_CONTEXT * ) hDNSRecvBuffer;

	dwError = DNSSelect( hDNSHandle );
	BAIL_ON_ERROR( dwError );

	dwRead = recv( pDNSContext->s, ( char * ) &wnBytesToRead,
		       sizeof( int16 ), 0 );
	if ( dwRead == SOCKET_ERROR ) {
		dwError = WSAGetLastError(  );
		BAIL_ON_ERROR( dwError );
	}

	wBytesToRead = ntohs( wnBytesToRead );

	dwError = DNSSelect( hDNSHandle );
	BAIL_ON_ERROR( dwError );

	dwRead = recv( pDNSContext->s,
		       ( char * ) pDNSRecvContext->pRecvBuffer, wBytesToRead,
		       0 );
	if ( dwRead == SOCKET_ERROR ) {
		dwError = WSAGetLastError(  );
		BAIL_ON_ERROR( dwError );
	}

	pDNSRecvContext->dwBytesRecvd = dwRead;

	*pdwBytesRead = ( int32 ) dwRead;

	return dwError;

      error:

	return dwError;
}

/********************************************************************
********************************************************************/

static int32 DNSUDPReceiveBufferContext( HANDLE hDNSHandle,
			    HANDLE hDNSRecvBuffer, int32 * pdwBytesRead )
{
	int32 dwError = 0;
	int32 dwRead = 0;
	DNS_CONNECTION_CONTEXT *pDNSContext = NULL;
	DNS_RECEIVEBUFFER_CONTEXT *pDNSRecvContext = NULL;

	pDNSContext = ( DNS_CONNECTION_CONTEXT * ) hDNSHandle;
	pDNSRecvContext = ( DNS_RECEIVEBUFFER_CONTEXT * ) hDNSRecvBuffer;

	dwError = DNSSelect( hDNSHandle );
	BAIL_ON_ERROR( dwError );

	dwRead = recv( pDNSContext->s,
		       ( char * ) pDNSRecvContext->pRecvBuffer, 512, 0 );
	if ( dwRead == SOCKET_ERROR ) {
		dwError = WSAGetLastError(  );
		BAIL_ON_ERROR( dwError );
	}

	pDNSRecvContext->dwBytesRecvd = dwRead;

	*pdwBytesRead = ( int32 ) dwRead;

      error:

	return dwError;
}

/********************************************************************
********************************************************************/

int32 DNSReceiveBufferContext( HANDLE hDNSHandle,
			 HANDLE hDNSRecvBuffer, int32 * pdwBytesRead )
{
	int32 dwError = 0;
	DNS_CONNECTION_CONTEXT *pDNSContext = NULL;

	pDNSContext = ( DNS_CONNECTION_CONTEXT * ) hDNSHandle;

	switch ( pDNSContext->hType ) {
	case DNS_TCP:
		dwError =
			DNSTCPReceiveBufferContext( hDNSHandle,
						    hDNSRecvBuffer,
						    pdwBytesRead );
		break;
	case DNS_UDP:
		dwError =
			DNSUDPReceiveBufferContext( hDNSHandle,
						    hDNSRecvBuffer,
						    pdwBytesRead );
		break;
	}
	return dwError;
}

/********************************************************************
********************************************************************/

int32 DNSCreateSendBuffer( HANDLE * phDNSSendBuffer )
{
	int32 dwError = 0;
	DNS_SENDBUFFER_CONTEXT *pDNSContext = NULL;
	uint8 *pSendBuffer = NULL;

	dwError = DNSAllocateMemory( sizeof( DNS_SENDBUFFER_CONTEXT ),
				     ( void * ) &pDNSContext );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSAllocateMemory( SENDBUFFER_SIZE,
				   ( void * ) &pSendBuffer );
	BAIL_ON_ERROR( dwError );

	pDNSContext->pSendBuffer = pSendBuffer;
	pDNSContext->dwBufferSize = SENDBUFFER_SIZE;

	/* We will offset into the buffer by 2 bytes
	   If we are doing a TCP write; we will fill in these
	   two bytes and send + 2 bytes
	   If we are doing a UDP write; we will start our send
	   +2 bytes and only send dwWritten; */

	pDNSContext->dwBufferOffset += 2;

	*phDNSSendBuffer = ( HANDLE ) pDNSContext;

	return dwError;

      error:

	if ( pSendBuffer ) {
		DNSFreeMemory( pSendBuffer );
	}
	if ( pDNSContext ) {
		DNSFreeMemory( pDNSContext );
	}
	*phDNSSendBuffer = ( HANDLE ) NULL;

	return dwError;
}


/********************************************************************
********************************************************************/

int32 DNSMarshallBuffer( HANDLE hDNSSendBuffer,
		   uint8 * pDNSSendBuffer,
		   int32 dwBufferSize, int32 * pdwBytesWritten )
{
	int32 dwError = 0;
	uint8 *pTemp = NULL;
	DNS_SENDBUFFER_CONTEXT *pDNSContext = NULL;

/* BugBug - we need to check for amount of space remaining in the
SendBuffer Context - if its insufficent, we want to realloc the 
Buffer and copy the context; Right now the assumption is we have a big
enough buffer */

	pDNSContext = ( DNS_SENDBUFFER_CONTEXT * ) hDNSSendBuffer;

	pTemp = pDNSContext->pSendBuffer + pDNSContext->dwBufferOffset;

	memcpy( pTemp, pDNSSendBuffer, dwBufferSize );

	pDNSContext->dwBytesWritten += dwBufferSize;
	pDNSContext->dwBufferOffset += dwBufferSize;

	*pdwBytesWritten = dwBufferSize;

	return dwError;
}

/********************************************************************
********************************************************************/

static int32 DNSTCPSendBufferContext( HANDLE hDNSServer,
			 HANDLE hSendBuffer, int32 * pdwBytesSent )
{
	DNS_SENDBUFFER_CONTEXT *pSendBufferContext = NULL;
	int32 dwError = 0;
	int16 wBytesWritten = 0;
	int16 wnBytesWritten = 0;

	pSendBufferContext = ( DNS_SENDBUFFER_CONTEXT * ) hSendBuffer;

	wBytesWritten = ( int16 ) pSendBufferContext->dwBytesWritten;
	wnBytesWritten = htons( wBytesWritten );

	memcpy( pSendBufferContext->pSendBuffer, &wnBytesWritten,
		sizeof( int16 ) );

	dwError = DNSSendTCPRequest( hDNSServer,
				     pSendBufferContext->pSendBuffer,
				     pSendBufferContext->dwBytesWritten + 2,
				     pdwBytesSent );
	BAIL_ON_ERROR( dwError );

      error:

	return dwError;
}

/********************************************************************
********************************************************************/

static int32 DNSUDPSendBufferContext( HANDLE hDNSServer,
			 HANDLE hSendBuffer, int32 * pdwBytesSent )
{
	DNS_SENDBUFFER_CONTEXT *pSendBufferContext = NULL;
	int32 dwError = 0;

	pSendBufferContext = ( DNS_SENDBUFFER_CONTEXT * ) hSendBuffer;

	/* Now remember to send 2 bytes ahead of pSendBuffer; because
	   we ignore the 2 bytes size field. */

	dwError = DNSSendUDPRequest( hDNSServer,
				     pSendBufferContext->pSendBuffer + 2,
				     pSendBufferContext->dwBytesWritten,
				     pdwBytesSent );
	BAIL_ON_ERROR( dwError );

      error:

	return dwError;
}

/********************************************************************
********************************************************************/

int32 DNSSendBufferContext( HANDLE hDNSServer,
		      HANDLE hSendBuffer, int32 * pdwBytesSent )
{
	DNS_CONNECTION_CONTEXT *pDNSContext = NULL;
	int32 dwError = 0;

	pDNSContext = ( DNS_CONNECTION_CONTEXT * ) hDNSServer;

	switch ( pDNSContext->hType ) {
	case DNS_TCP:
		dwError = DNSTCPSendBufferContext( hDNSServer,
						   hSendBuffer,
						   pdwBytesSent );
		BAIL_ON_ERROR( dwError );
		break;

	case DNS_UDP:
		dwError = DNSUDPSendBufferContext( hDNSServer,
						   hSendBuffer,
						   pdwBytesSent );
		BAIL_ON_ERROR( dwError );
		break;
	}
      error:

	return dwError;
}

/********************************************************************
********************************************************************/

int32 DNSDumpSendBufferContext( HANDLE hSendBuffer )
{
	DNS_SENDBUFFER_CONTEXT *pSendBufferContext = NULL;
	int32 dwError = 0;
	int32 dwCurLine = 0;
	int32 i = 0;

	pSendBufferContext = ( DNS_SENDBUFFER_CONTEXT * ) hSendBuffer;
	printf( "\n" );
	printf( "Buffer Size is: %d\n", pSendBufferContext->dwBytesWritten );
	while ( i < pSendBufferContext->dwBytesWritten ) {
		if ( ( i / 16 ) > dwCurLine ) {
			printf( "\n" );
			dwCurLine++;
		}
		if ( ( i % 8 ) == 0 ) {
			printf( "  " );
		}
		printf( "%.2x ", pSendBufferContext->pSendBuffer[i] );
		i++;
	}
	return dwError;
}

/********************************************************************
********************************************************************/

int32 DNSDumpRecvBufferContext( HANDLE hRecvBuffer )
{
	DNS_RECEIVEBUFFER_CONTEXT *pRecvBufferContext = NULL;
	int32 dwError = 0;
	int32 dwCurLine = 0;
	int32 i = 0;

	pRecvBufferContext = ( DNS_RECEIVEBUFFER_CONTEXT * ) hRecvBuffer;

	printf( "\n" );
	printf( "Buffer Size is: %d\n", pRecvBufferContext->dwBytesRecvd );

	while ( i < pRecvBufferContext->dwBytesRecvd ) {
		if ( ( i / 16 ) > dwCurLine ) {
			printf( "\n" );
			dwCurLine++;
		}
		if ( ( i % 8 ) == 0 ) {
			printf( "  " );
		}
		printf( "%.2x ", pRecvBufferContext->pRecvBuffer[i] );
		i++;
	}
	return dwError;
}

/********************************************************************
********************************************************************/

int32 DNSCreateReceiveBuffer( HANDLE * phDNSRecvBuffer )
{
	int32 dwError = 0;
	DNS_RECEIVEBUFFER_CONTEXT *pDNSContext = NULL;
	uint8 *pRecvBuffer = NULL;

	dwError = DNSAllocateMemory( sizeof( DNS_RECEIVEBUFFER_CONTEXT ),
				     ( void * ) &pDNSContext );
	BAIL_ON_ERROR( dwError );

	dwError =
		DNSAllocateMemory( RECVBUFFER_SIZE,
				   ( void * ) &pRecvBuffer );
	BAIL_ON_ERROR( dwError );

	pDNSContext->pRecvBuffer = pRecvBuffer;
	pDNSContext->dwBufferSize = RECVBUFFER_SIZE;

	*phDNSRecvBuffer = ( HANDLE ) pDNSContext;

	return dwError;

      error:

	if ( pRecvBuffer ) {
		DNSFreeMemory( pRecvBuffer );
	}
	if ( pDNSContext ) {
		DNSFreeMemory( pDNSContext );
	}
	*phDNSRecvBuffer = ( HANDLE ) NULL;

	return dwError;
}

/********************************************************************
********************************************************************/

int32 DNSUnmarshallBuffer( HANDLE hDNSRecvBuffer,
		     uint8 * pDNSRecvBuffer,
		     int32 dwBufferSize, int32 * pdwBytesRead )
{
	int32 dwError = 0;
	uint8 *pTemp = NULL;
	DNS_RECEIVEBUFFER_CONTEXT *pDNSContext = NULL;

/* BugBug - we need to check for amount of space remaining in the
SendBuffer Context - if its insufficent, we want to realloc the 
Buffer and copy the context; Right now the assumption is we have a big
enough buffer */

	pDNSContext = ( DNS_RECEIVEBUFFER_CONTEXT * ) hDNSRecvBuffer;

	pTemp = pDNSContext->pRecvBuffer + pDNSContext->dwBytesRead;

	memcpy( pDNSRecvBuffer, pTemp, dwBufferSize );

	pDNSContext->dwBytesRead += dwBufferSize;

	*pdwBytesRead = dwBufferSize;

	return dwError;
}

/********************************************************************
********************************************************************/

int32 DNSUnmarshallDomainNameAtOffset( HANDLE hRecvBuffer,
				 int16 wOffset,
				 DNS_DOMAIN_NAME ** ppDomainName )
{
	int32 dwError = 0;
	DNS_DOMAIN_LABEL *pLabel = NULL;
	DNS_DOMAIN_LABEL *pLabelList = NULL;
	DNS_DOMAIN_NAME *pDomainName = NULL;
	char *pszLabel = NULL;
	char szLabel[65];
	uint8 uLen = 0;
	int32 dwCurrent = 0;
	DNS_RECEIVEBUFFER_CONTEXT *pRecvContext = NULL;

	pRecvContext = ( DNS_RECEIVEBUFFER_CONTEXT * ) hRecvBuffer;
	dwCurrent = wOffset;

	while ( 1 ) {

		memcpy( &uLen, pRecvContext->pRecvBuffer + dwCurrent,
			sizeof( char ) );
		dwCurrent++;

		if ( uLen == 0 ) {
			break;
		}

		memset( szLabel, 0, 65 );
		memcpy( szLabel, pRecvContext->pRecvBuffer + dwCurrent,
			uLen );
		dwCurrent += uLen;

		dwError = DNSAllocateString( szLabel, &pszLabel );
		BAIL_ON_ERROR( dwError );

		dwError =
			DNSAllocateMemory( sizeof( DNS_DOMAIN_LABEL ),
					   ( void * ) &pLabel );
		BAIL_ON_ERROR( dwError );

		pLabel->pszLabel = pszLabel;
		dwError = DNSAppendLabel( pLabelList, pLabel, &pLabelList );
		BAIL_ON_ERROR( dwError );
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

/********************************************************************
********************************************************************/

int32 DNSReceiveBufferMoveBackIndex( HANDLE hRecvBuffer, int16 wOffset )
{
	int32 dwError = 0;
	DNS_RECEIVEBUFFER_CONTEXT *pDNSContext = NULL;

	pDNSContext = ( DNS_RECEIVEBUFFER_CONTEXT * ) hRecvBuffer;
	pDNSContext->dwBytesRead -= wOffset;

	return dwError;
}

/********************************************************************
********************************************************************/

void DNSFreeSendBufferContext( HANDLE hSendBuffer )
{
	DNS_SENDBUFFER_CONTEXT *pSendBufferContext = NULL;

	pSendBufferContext = ( DNS_SENDBUFFER_CONTEXT * ) hSendBuffer;

	if ( pSendBufferContext && pSendBufferContext->pSendBuffer ) {
		DNSFreeMemory( pSendBufferContext->pSendBuffer );
	}
	if ( pSendBufferContext ) {
		DNSFreeMemory( pSendBufferContext );
	}
}

/********************************************************************
********************************************************************/

int32 DNSGetSendBufferContextSize( HANDLE hSendBuffer )
{
	DNS_SENDBUFFER_CONTEXT *pSendBufferContext = NULL;

	pSendBufferContext = ( DNS_SENDBUFFER_CONTEXT * ) hSendBuffer;

	return ( pSendBufferContext->dwBytesWritten );

}

/********************************************************************
********************************************************************/

uint8 *DNSGetSendBufferContextBuffer( HANDLE hSendBuffer )
{
	DNS_SENDBUFFER_CONTEXT *pSendBufferContext = NULL;

	pSendBufferContext = ( DNS_SENDBUFFER_CONTEXT * ) hSendBuffer;

	return ( pSendBufferContext->pSendBuffer );
}

