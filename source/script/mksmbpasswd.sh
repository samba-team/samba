#!/bin/sh
awk 'BEGIN {FS=":"
	printf("#\n# SMB password file.\n#\n")
	}
{ printf( "%s:%s:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:%s:%s:%s\n", $1, $3, $5, $6, $7) }
'
