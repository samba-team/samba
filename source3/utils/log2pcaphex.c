/* 
Unix SMB/CIFS implementation.
Utility to extract pcap files from samba (log level 10) log files

Copyright (C) Jelmer Vernooij 2003
Thanks to Tim Potter for the genial idea

Example use: log2pcaphex < samba-log-file | text2pcap -T 139,139 - foo.pcap

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include <assert.h>


#define itoa(a) ((a) < 0xa?'0'+(a):'A' + (a-0xa))

void print_packet(FILE *out, char *data, long length)
{
long i,cur = 0;int tmp;
while(cur < length) {
	fprintf(out, "%06X ", cur);
	for(i = cur; i < length && i < cur + 16; i++) {
		fprintf(out, "%02x ", (unsigned char)data[i]);
	}
	
	cur = i;
	fprintf(out, "\n");
}
}

char *curpacket = NULL;
long curpacket_len = 0;

long read_log_msg(FILE *in, char **_buffer, long *buffersize)
{
	char *buffer;
	int tmp; long i;
	assert(fscanf(in, " size=%d\n", buffersize));
	*buffersize+=4; /* for netbios */
	buffer = malloc(*buffersize);
	memset(buffer, 0, *buffersize);
	/* NetBIOS */
	buffer[0] = 0x00;
	buffer[1] = 0x00;
	memcpy(buffer+2, &buffersize, 2);
	buffer[4] = 0xFF;
	buffer[5] = 'S';
	buffer[6] = 'M';
	buffer[7] = 'B';
	assert(fscanf(in, "  smb_com=0x%x\n", &tmp)); buffer[smb_com] = tmp;
	assert(fscanf(in, "  smb_rcls=%d\n", &tmp)); buffer[smb_rcls] = tmp;
	assert(fscanf(in, "  smb_reh=%d\n", &tmp)); buffer[smb_reh] = tmp;
	assert(fscanf(in, "  smb_err=%d\n", &tmp)); memcpy(buffer+smb_err, &tmp, 2);
	assert(fscanf(in, "  smb_flg=%d\n", &tmp)); buffer[smb_flg] = tmp;
	assert(fscanf(in, "  smb_flg2=%d\n", &tmp)); memcpy(buffer+smb_flg2, &tmp, 2);
	assert(fscanf(in, "  smb_tid=%d\n", &tmp)); memcpy(buffer+smb_tid, &tmp, 2);
	assert(fscanf(in, "  smb_pid=%d\n", &tmp)); memcpy(buffer+smb_pid, &tmp, 2);
	assert(fscanf(in, "  smb_uid=%d\n", &tmp)); memcpy(buffer+smb_uid, &tmp, 2);
	assert(fscanf(in, "  smb_mid=%d\n", &tmp)); memcpy(buffer+smb_mid, &tmp, 2);
	assert(fscanf(in, "  smt_wct=%d\n", &tmp)); buffer[smb_wct] = tmp;
	for(i = 0; i < buffer[smb_wct]; i++) {
		assert(fscanf(in, "  smb_vwv[%*2d]=%*5d (0x%X)\n", &tmp));
		memcpy(buffer+smb_vwv+i*2, &tmp, 2);
	}

	assert(fscanf(in, "  smb_bcc=%d\n", &tmp)); memcpy(buffer+smb_vwv+(1+buffer[smb_wct])*2, &tmp, 2);
	*_buffer = buffer;
	return tmp;
}

void read_log_data(FILE *in, char *buffer, long *buffersize, long data_offset)
{
	int addr, b[16]; long i,j;
	for(i = *buffersize-data_offset; i < *buffersize; i++) {
		fscanf(in, "  [%x] %2x %2x %2x %2x %2x %2x %2x %2x  %2x %2x %2x %2x %2x %2x %2x %2x\n", &addr, 	&b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &b[6], &b[7], &b[8], &b[9], &b[10], &b[11], &b[12], &b[13], &b[14], &b[15]);
		for(j = i; j < 16 && j < *buffersize; j++) buffer[j] = b[j-i];
	}
}

int main (int argc, char **argv)
{
	const char *infile, *outfile;
	FILE *out, *in;
	int opt;
	int c;
	poptContext pc;
	char buffer[4096];
	long data_offset;
	int in_packet = 0;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		POPT_TABLEEND
	};
	
	pc = poptGetContext(NULL, argc, (const char **) argv, long_options,
			    POPT_CONTEXT_KEEP_FIRST);
	poptSetOtherOptionHelp(pc, "[<infile> [<outfile>]]");
	
	
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		}
	}

	poptGetArg(pc); /* Drop argv[0], the program name */

	infile = poptGetArg(pc);

	if(infile) {
		in  = fopen(infile, "r");
		if(!in) {
			perror("fopen");
			return 1;
		}
	} else in = stdin;
	
	outfile = poptGetArg(pc);

	if(outfile) {
		out = fopen(outfile, "w+");
		if(!out) { 
			perror("fopen"); 
			fprintf(stderr, "Can't find %s, using stdout...\n", outfile);
		}
	}

	if(!outfile) out = stdout;

	while(!feof(in)) {
		
		fgets(buffer, sizeof(buffer), in);
		if(buffer[0] == '[') { /* Header */
			if(strstr(buffer, "show_msg")) {
				in_packet++;
				if(in_packet == 1)continue;
				data_offset = read_log_msg(in, &curpacket, &curpacket_len);
			} else if(in_packet && strstr(buffer, "dump_data")) {
				read_log_data(in, curpacket, &curpacket_len, data_offset);
			}  else { 
				if(in_packet){ 
					print_packet(out, curpacket, curpacket_len); 
					free(curpacket); 
				}
				in_packet = 0;
			}
		} 
	}

	return 0;
}
