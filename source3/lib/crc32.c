/* 
 * Dr Dobb's Journal: http://www.ddj.com/ftp/1992/1992.05/crcman.zip
 *
 * Copyright Mark R. Nelson 1992
 *
 * This code used by permission of J Erickson <jerickson@ddj.com>
 * Tues 6th October 1998.  Copyright acknowledged above, as agreed.
 *
 */

#include "includes.h"

#define CRC32_POLYNOMIAL     0xEDB88320L

/*****************************************************************
 Instead of performing a straightforward calculation of the 32 bit
 CRC using a series of logical operations, this program uses the
 faster table lookup method.  This routine is called once when the
 program starts up to build the table which will be used later
 when calculating the CRC values.
 *****************************************************************/

static uint32 CRCTable[256];

void crc32_build_table(void)
{
	int i;
	int j;
	uint32 crc;

	for ( i = 0; i <= 255 ; i++ )
	{
		crc = i;
		for ( j = 8 ; j > 0; j-- )
		{
			if ( crc & 1 )
			{
				crc = ( crc >> 1 ) ^ CRC32_POLYNOMIAL;
			}
			else
			{
				crc >>= 1;
			}
		}
		CRCTable[ i ] = crc;
	}
}

/*****************************************************************
 This routine calculates the CRC for a block of data using the
 table lookup method. 
 *****************************************************************/

uint32 crc32_calc_buffer( uint32 count, char *buffer)
{
	char *p;
	uint32 crc;

	p = buffer;
	crc = 0xffffffff;

	while ( count-- != 0 )
	{
		uint32 temp1;
		uint32 temp2;

		temp1 = ( crc >> 8 ) & 0x00FFFFFFL;
		temp2 = CRCTable[ ( (int) crc ^ *p++ ) & 0xff ];
		crc = temp1 ^ temp2;
	}
	return crc;
}

