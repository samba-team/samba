/* a tool to open a scsi device and issue some useful commands
   such as INQUIRY and helpers to call various PERSISTENT RESERVATION
   functions

   Copyright   ronnie sahlberg 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

/* very incomplete and needs to be enhanced with noice command line options
   to drive it.
   we need access to an array that supports the PERSISTENT RESERVATION cdb's
   before we can proceed
*/
/* scsi bugs:
   INQUIRY takes a 2 byte allocation_length parameter but it appears that 
   it only looks at the low byte. If you specify 0x00ff all is well
   but if you specify 0x0100   it gets confused and returnes garbage data
   for (e.g) SupportedVPDPages. Same goes for UnitSerialNumber and probably all
   other inq pages as well.

*/

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>
#include "popt.h"


#define SCSI_TIMEOUT 5000 /* ms */

static char *command = NULL;
static char *device  = NULL;
static char *key     = NULL;
static char *rmkey     = NULL;
static int scope = -1;
static int type  = -1;

const char *sensetable[16]={
	"no sense",
	"recovered error",
	"not ready",
	"medium error",
	"hardware error",
	"illegal request",
	"unit attention",
	"data protect",
	"blank check",
	"vendor specific",
	"copy aborted",
	"aboreted command",
	"unknown",
	"unknown",
	"unknown",
	"unknown"
};

int scsi_io(int fd, unsigned char *cdb, unsigned char cdb_size, int xfer_dir, unsigned char *data, unsigned int *data_size, unsigned char *sense, unsigned int *sense_len)
{
	sg_io_hdr_t io_hdr;

	memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
	io_hdr.interface_id = 'S';

	/* CDB */
	io_hdr.cmdp = cdb;
	io_hdr.cmd_len = cdb_size;

	/* Where to store the sense_data, if there was an error */
	io_hdr.sbp = sense;
	io_hdr.mx_sb_len = *sense_len;
	*sense_len=0;

	/* Transfer direction, either in or out. Linux does not yet
	   support bidirectional SCSI transfers ?
	 */
	io_hdr.dxfer_direction = xfer_dir;

	/* Where to store the DATA IN/OUT from the device and how big the
	   buffer is
	 */
	io_hdr.dxferp = data;
	io_hdr.dxfer_len = *data_size;

	/* SCSI timeout in ms */
	io_hdr.timeout = SCSI_TIMEOUT;


	if(ioctl(fd, SG_IO, &io_hdr) < 0){
		perror("SG_IO ioctl failed");
		return -1;
	}

	/* now for the error processing */
	if((io_hdr.info & SG_INFO_OK_MASK) != SG_INFO_OK){
		if(io_hdr.sb_len_wr > 0){
			*sense_len=io_hdr.sb_len_wr;
			return 0;
		}
	}
	if(io_hdr.masked_status){
		printf("status=0x%x\n", io_hdr.status);
		printf("masked_status=0x%x\n", io_hdr.masked_status);
		return -2;
	}
	if(io_hdr.host_status){
		printf("host_status=0x%x\n", io_hdr.host_status);
		return -3;
	}
	if(io_hdr.driver_status){
		printf("driver_status=0x%x\n", io_hdr.driver_status);
		return -4;
	}

#if 0
{int i;
printf("CDB:\n");
for(i=0;i<cdb_size;i++){printf("0x%02x ",cdb[i]);if((i%8)==7)printf("\n");}
printf("\n");
}
{int i;
printf("DATA:\n");
for(i=0;i<96;i++){printf("0x%02x ",data[i]);if((i%8)==7)printf("\n");}
printf("\n");
}
#endif

	return 0;
}

typedef struct _value_string_t {
	int	value;
	const char	*string;
} value_string_t;



value_string_t peripheral_device_types[] = {
	{0, "SBC : Direct Access Block device"},
	{1, "SSC : Sequential Access Device"},
	{5, "MMC : Multimedia Device"},
	{17,"OSD : Object Based Storage"},
	{0,NULL}
};

value_string_t scsi_versions[] = {
	{0, "No conformance to any standard claimed"},
	{3, "SPC"},
	{4, "SPC-2"},
	{5, "SPC-3"},
	{0,NULL}
};

value_string_t vpd_pages[] = {
	{0x00, "Supported VPD Pages"},
	{0x80, "Unit Serial number"},
	{0x83, "Device Identification"},
	{0,NULL}
};

const char *val_to_str(value_string_t *vs, int v)
{
	while(vs && vs->string){
		if(vs->value==v){
			return vs->string;
		}
		vs++;
	}
	return "";
}

void print_sense_data(unsigned char *sense, int sense_len)
{
	int i;
	unsigned char asc, ascq;

	printf("Device returned sense information\n");
	if(sense[0]==0x70){
		printf("filemark:%d eom:%d ili:%d  sense-key:0x%02x (%s)\n",
			!!(sense[2]&0x80),
			!!(sense[2]&0x40),
			!!(sense[2]&0x20),
			sense[2]&0x0f,
			sensetable[sense[2]&0x0f]);
		printf("command specific info: 0x%02x 0x%02x 0x%02x 0x%02x\n",
			sense[8],sense[9],sense[10],sense[11]);

		asc=sense[12];
		printf("additional sense code:0x%02x\n", asc);

		ascq=sense[13];
		printf("additional sense code qualifier:0x%02x\n", ascq);

		printf("field replacable unit code:0x%02x\n", sense[14]);

		if((asc==0x20)&&(ascq==0x00))
			printf("INVALID COMMAND OPERATION CODE\n");
	}

	printf("Sense data:\n");
	for(i=0;i<sense_len;i++){
		printf("0x%02x ", sense[i]);
		if((i%8)==7)printf("\n");
	}
	printf("\n");
}

int scsi_inquiry(int fd)
{
	unsigned char cdb[]={0x12,0,0,0,0,0};

	unsigned int data_size=96;
	unsigned char data[data_size];

	unsigned int sense_len=32;
	unsigned char sense[sense_len];

	int res, i;

	cdb[3]=(data_size>>8)&0xff;
	cdb[4]=data_size&0xff;


	printf("Standard INQUIRY Data:\n");

	res=scsi_io(fd, cdb, sizeof(cdb), SG_DXFER_FROM_DEV, data, &data_size, sense, &sense_len);
	if(res){
		printf("SCSI_IO failed\n");
		return -1;
	}
	if(sense_len){
		print_sense_data(sense, sense_len);
		return -1;
	}

	/* Peripheral Qualifier */
	printf("Peripheral Qualifier:%c%c%cb\n",
		'0'+!!(data[0]&0x80),
		'0'+!!(data[0]&0x40),
		'0'+!!(data[0]&0x20));

	/* Peripheral Device Type */
	printf("Peripheral Device Type: 0x%02x (%s)\n",
		data[0]&0x1f,
		val_to_str(peripheral_device_types, data[0]&0x1f));

	/* RMB */
	printf("RMB: %s device\n", data[1]&0x80?"REMOVABLE":"NON-REMOVABLE");

	/* SCSI Version */
	printf("SCSI Version: 0x%02x (%s)\n",
		data[2],
		val_to_str(scsi_versions, data[2]));

	/* NormACA, HiSUP, Response Data Format */
	printf("NormACA:%d HiSup:%d ResponseDataFormat:%d\n",
		!!(data[3]&0x20),
		!!(data[3]&0x10),
		data[3]&0x0f);

	switch(data[3]&0x0f){
	/*SPC-2/SPC-3/SPC-4*/
	case 2:
	/*SPC (not strictly correct but we print it like 2 anyway)*/
	case 1:
		/* SCCS ... */
		printf("SCCS:%d ACC:%d TPGS:%c%cb 3PC:%d PROTECT:%d\n",
			!!(data[5]&0x80),
			!!(data[5]&0x40),
			'0'+!!(data[5]&0x20),
			'0'+!!(data[5]&0x10),
			!!(data[5]&0x08),
			!!(data[5]&0x01));

		/* Encserv ... */
		printf("Encserv:%d VS:%d MultiP:%d ADDR16:%d\n",
			!!(data[6]&0x40),
			!!(data[6]&0x20),
			!!(data[6]&0x10),
			!!(data[6]&0x01));

		/* WBUS16 ... */
		printf("WBUS16:%d SYNC:%d CmdQue:%d VS:%d\n",
			!!(data[7]&0x20),
			!!(data[7]&0x10),
			!!(data[7]&0x02),
			!!(data[7]&0x01));
			

		/* T10 vendor Identification */
		printf("Vendor:");
		for(i=0;i<8;i++)printf("%c",data[8+i]);printf("\n");
 
		/* Product Identification */
		printf("Product:");
		for(i=0;i<16;i++)printf("%c",data[16+i]);printf("\n");

		/* Product Revision Level */
		printf("Product Revision:");
		for(i=0;i<4;i++)printf("%c",data[32+i]);printf("\n");

		break;
	}
	
	return 0;
}

int scsi_inquiry_supported_vpd_pages(int fd)
{
	unsigned char cdb[]={0x12,0x01,0,0,0,0};

	unsigned int data_size=0xff;
	unsigned char data[data_size];

	unsigned int sense_len=32;
	unsigned char sense[sense_len];

	int res, pl, i;

	cdb[3]=(data_size>>8)&0xff;
	cdb[4]=data_size&0xff;


	printf("INQUIRY Supported VPD Pages:\n");

	res=scsi_io(fd, cdb, sizeof(cdb), SG_DXFER_FROM_DEV, data, &data_size, sense, &sense_len);
	if(res){
		printf("SCSI_IO failed\n");
		return -1;
	}
	if(sense_len){
		print_sense_data(sense, sense_len);
		return -1;
	}

	/* Page Length */
	pl=data[3];

	/* Pages */
	for(i=4;i<(pl+4);i++){
		printf("Page:%02xh (%s)\n",
			data[i],
			val_to_str(vpd_pages, data[i]));
	}

	return 0;
}

int scsi_inquiry_unit_serial_number(int fd)
{
	unsigned char cdb[]={0x12,0x01,0x80,0,0,0};

	unsigned int data_size=0x00ff;
	unsigned char data[data_size];

	unsigned int sense_len=32;
	unsigned char sense[sense_len];

	int res, pl, i;

	cdb[3]=(data_size>>8)&0xff;
	cdb[4]=data_size&0xff;


	printf("INQUIRY Unit Serial Number:\n");

	res=scsi_io(fd, cdb, sizeof(cdb), SG_DXFER_FROM_DEV, data, &data_size, sense, &sense_len);
	if(res){
		printf("SCSI_IO failed\n");
		return -1;
	}
	if(sense_len){
		print_sense_data(sense, sense_len);
		return -1;
	}

	/* Page Length */
	pl=data[3];

	/* Unit Serial Number */
	printf("Unit Serial Number:");
	for(i=4;i<(pl+4);i++)printf("%c",data[i]&0xff);printf("\n");

	return 0;
}

int scsi_persistent_reserve_in_read_keys(int fd)
{
	unsigned char cdb[]={0x5e,0,0,0,0,0,0,0,0,0};

	unsigned int data_size=0x00ff;
	unsigned char data[data_size];

	unsigned int sense_len=32;
	unsigned char sense[sense_len];
	unsigned char service_action=0;
	int res, i;
	unsigned long prgeneration, additional_length;

	cdb[1]=service_action;
	cdb[7]=(data_size>>8)&0xff;
	cdb[8]=data_size&0xff;


	printf("PERSISTENT RESERVE IN: READ KEYS\n");

	res=scsi_io(fd, cdb, sizeof(cdb), SG_DXFER_FROM_DEV, data, &data_size, sense, &sense_len);
	if(res){
		printf("SCSI_IO failed\n");
		return -1;
	}
	if(sense_len){
		print_sense_data(sense, sense_len);
		return -1;
	}

	/* PRGeneration */
	prgeneration=data[0];
	prgeneration<<=8;prgeneration|=data[1];
	prgeneration<<=8;prgeneration|=data[2];
	prgeneration<<=8;prgeneration|=data[3];
	printf("PRGeneration:%lu\n", prgeneration);

	/* Additional Length */
	additional_length=data[4];
	additional_length<<=8;additional_length|=data[5];
	additional_length<<=8;additional_length|=data[6];
	additional_length<<=8;additional_length|=data[7];
	printf("Additional Length:%lu\n", additional_length);

	/* print the registered keys */
	for(i=0;i<additional_length;i+=8){
		printf("Key:%02x%02x%02x%02x%02x%02x%02x%02x\n",
			data[i+8],
			data[i+9],
			data[i+10],
			data[i+11],
			data[i+12],
			data[i+13],
			data[i+14],
			data[i+15]);
	}

	return 0;
}

int scsi_persistent_reserve_in_read_reservation(int fd)
{
	unsigned char cdb[]={0x5e,0,0,0,0,0,0,0,0,0};

	unsigned int data_size=0x00ff;
	unsigned char data[data_size];

	unsigned int sense_len=32;
	unsigned char sense[sense_len];
	unsigned char service_action=1;
	int res;
	unsigned long prgeneration, additional_length;

	cdb[1]=service_action;
	cdb[7]=(data_size>>8)&0xff;
	cdb[8]=data_size&0xff;


	printf("PERSISTENT RESERVE IN: READ RESERVATION\n");

	res=scsi_io(fd, cdb, sizeof(cdb), SG_DXFER_FROM_DEV, data, &data_size, sense, &sense_len);
	if(res){
		printf("SCSI_IO failed\n");
		return -1;
	}
	if(sense_len){
		print_sense_data(sense, sense_len);
		return -1;
	}

	/* PRGeneration */
	prgeneration=data[0];
	prgeneration<<=8;prgeneration|=data[1];
	prgeneration<<=8;prgeneration|=data[2];
	prgeneration<<=8;prgeneration|=data[3];
	printf("PRGeneration:%lu\n", prgeneration);

	/* Additional Length */
	additional_length=data[4];
	additional_length<<=8;additional_length|=data[5];
	additional_length<<=8;additional_length|=data[6];
	additional_length<<=8;additional_length|=data[7];
	printf("Additional Length:%lu\n", additional_length);

	if(additional_length==16){
		printf("Key:%02x%02x%02x%02x%02x%02x%02x%02x\n",
			data[8],
			data[9],
			data[10],
			data[11],
			data[12],
			data[13],
			data[14],
			data[15]);
		printf("Scope:%xh Type:%xh\n",data[21]>>4,data[21]&0x0f);
	}

	return 0;
}

int scsi_persistent_reserve_in_report_capabilities(int fd)
{
	unsigned char cdb[]={0x5e,0,0,0,0,0,0,0,0,0};

	unsigned int data_size=0x00ff;
	unsigned char data[data_size];

	unsigned int sense_len=32;
	unsigned char sense[sense_len];
	unsigned char service_action=2;
	int res;
	unsigned short length, type_mask;

	cdb[1]=service_action;
	cdb[7]=(data_size>>8)&0xff;
	cdb[8]=data_size&0xff;


	printf("PERSISTENT RESERVE IN: REPORT CAPABILITIES\n");

	res=scsi_io(fd, cdb, sizeof(cdb), SG_DXFER_FROM_DEV, data, &data_size, sense, &sense_len);
	if(res){
		printf("SCSI_IO failed\n");
		return -1;
	}
	if(sense_len){
		print_sense_data(sense, sense_len);
		return -1;
	}

	/* Length */
	length=data[0];
	length<<=8;length|=data[1];
	printf("Length:%d\n", length);

	/* CRH ... */
	printf("CRH:%d SIP_C:%d ATP_C:%d PTPL_C:%d\n",
		!!(data[2]&0x10),
		!!(data[2]&0x08),
		!!(data[2]&0x04),
		!!(data[2]&0x01));

	/* TMV ... */
	printf("TMV:%d ALLOW_COMMANDS:%c%c%cb PTPL_A:%d\n",
		!!(data[3]&0x80),
		'0'+(!!(data[3]&0x40)),
		'0'+(!!(data[3]&0x20)),
		'0'+(!!(data[3]&0x10)),
		!!(data[3]&0x01));

	/* Persistent Reservation Type Mask */
	type_mask=data[4];
	type_mask<<=8;type_mask|=data[5];
	printf("Persistent Reservation Type Mask:0x%04x\n", type_mask);
	printf("WR_EX_AR:%d EX_AC_RO:%d WR_EX_RO:%d EX_AC:%d WR_EX:%d EX_AC_AR:%d\n",
		!!(data[4]&0x80),
		!!(data[4]&0x40),
		!!(data[4]&0x20),
		!!(data[4]&0x08),
		!!(data[4]&0x02),
		!!(data[4]&0x01));

	return 0;
}

int scsi_persistent_reserve_in_read_full_status(int fd)
{
	unsigned char cdb[]={0x5e,0,0,0,0,0,0,0,0,0};

	unsigned int data_size=0x00ff;
	unsigned char data[data_size];

	unsigned int sense_len=32;
	unsigned char sense[sense_len];
	unsigned char service_action=3;
	int res;
	unsigned long prgeneration, additional_length;

	cdb[1]=service_action;
	cdb[7]=(data_size>>8)&0xff;
	cdb[8]=data_size&0xff;


	printf("PERSISTENT RESERVE IN: READ FULL STATUS\n");

	res=scsi_io(fd, cdb, sizeof(cdb), SG_DXFER_FROM_DEV, data, &data_size, sense, &sense_len);
	if(res){
		printf("SCSI_IO failed\n");
		return -1;
	}
	if(sense_len){
		print_sense_data(sense, sense_len);
		return -1;
	}

	/* PRGeneration */
	prgeneration=data[0];
	prgeneration<<=8;prgeneration|=data[1];
	prgeneration<<=8;prgeneration|=data[2];
	prgeneration<<=8;prgeneration|=data[3];
	printf("PRGeneration:%lu\n", prgeneration);

	/* Additional Length */
	additional_length=data[4];
	additional_length<<=8;additional_length|=data[5];
	additional_length<<=8;additional_length|=data[6];
	additional_length<<=8;additional_length|=data[7];
	printf("Additional Length:%lu\n", additional_length);

/*XXX*/

	return 0;
}

int scsi_persistent_reserve_out_clear(int fd)
{
	unsigned char cdb[]={0x5f,0,0,0,0,0,0,0,0,0};

	unsigned int data_size=24;
	unsigned char data[data_size];

	unsigned int sense_len=32;
	unsigned char sense[sense_len];
	unsigned char service_action=3;
	int res;

	long long k;

	if (scope==-1) {
		printf("Must specify scope\n");
		printf("scsi_io --device=<DEVICE> --command=clear --scope=<SCOPE> --type=<TYPE> --key=<KEY>\n");
		_exit(10);
	}
	if (type==-1) {
		printf("Must specify type\n");
		printf("scsi_io --device=<DEVICE> --command=clear --scope=<SCOPE> --type=<TYPE> --key=<KEY>\n");
		_exit(10);
	}
	if (!key) {
		printf("Must specify key\n");
		printf("scsi_io --device=<DEVICE> --command=clear --scope=<SCOPE> --type=<TYPE> --key=<KEY>\n");
		_exit(10);
	}

	sscanf(key, "%llx", &k);
	cdb[1]=service_action;
	cdb[2]=(scope<<4)|type;
	cdb[7]=(data_size>>8)&0xff;
	cdb[8]=data_size&0xff;

	memset(data, 0, data_size);

	/* Reservation Key */
	data[0]=(k>>56)&0xff;
	data[1]=(k>>48)&0xff;
	data[2]=(k>>40)&0xff;
	data[3]=(k>>32)&0xff;
	data[4]=(k>>24)&0xff;
	data[5]=(k>>16)&0xff;
	data[6]=(k>> 8)&0xff;
	data[7]=(k    )&0xff;

	/* Service Action Key */
	data[8]=0;
	data[9]=0;
	data[10]=0;
	data[11]=0;
	data[12]=0;
	data[13]=0;
	data[14]=0;
	data[15]=0;

	/* Spec_ip_ti=0 all_tg_pt=1 aptpl=0 */
	data[20]=0x04;

	printf("PERSISTENT RESERVE IN: CLEAR\n");

	res=scsi_io(fd, cdb, sizeof(cdb), SG_DXFER_TO_DEV, data, &data_size, sense, &sense_len);
	if(res){
		printf("SCSI_IO failed\n");
		return -1;
	}
	if(sense_len){
		print_sense_data(sense, sense_len);
		return -1;
	}

	return 0;
}

int scsi_persistent_reserve_out_reserve(int fd)
{
	unsigned char cdb[]={0x5f,0,0,0,0,0,0,0,0,0};

	unsigned int data_size=24;
	unsigned char data[data_size];

	unsigned int sense_len=32;
	unsigned char sense[sense_len];
	unsigned char service_action=1;
	int res;
	long long k;

	if (scope==-1) {
		printf("Must specify scope\n");
		printf("scsi_io --device=<DEVICE> --command=reserve --scope=<SCOPE> --type=<TYPE> --key=<KEY>\n");
		_exit(10);
	}
	if (type==-1) {
		printf("Must specify type\n");
		printf("scsi_io --device=<DEVICE> --command=reserve --scope=<SCOPE> --type=<TYPE> --key=<KEY>\n");
		_exit(10);
	}
	if (!key) {
		printf("Must specify key\n");
		printf("scsi_io --device=<DEVICE> --command=reserve --scope=<SCOPE> --type=<TYPE> --key=<KEY>\n");
		_exit(10);
	}

	sscanf(key, "%llx", &k);


	cdb[1]=service_action;
	cdb[2]=(scope<<4)|type;
	cdb[7]=(data_size>>8)&0xff;
	cdb[8]=data_size&0xff;

	memset(data, 0, data_size);

	/* Reservation Key */
	data[0]=(k>>56)&0xff;
	data[1]=(k>>48)&0xff;
	data[2]=(k>>40)&0xff;
	data[3]=(k>>32)&0xff;
	data[4]=(k>>24)&0xff;
	data[5]=(k>>16)&0xff;
	data[6]=(k>> 8)&0xff;
	data[7]=(k    )&0xff;

	/* Service Action Key */
	data[8]=0;
	data[9]=0;
	data[10]=0;
	data[11]=0;
	data[12]=0;
	data[13]=0;
	data[14]=0;
	data[15]=0;

	/* Spec_ip_ti=0 all_tg_pt=1 aptpl=0 */
	data[20]=0x04;

	printf("PERSISTENT RESERVE IN: RESERVE\n");

	res=scsi_io(fd, cdb, sizeof(cdb), SG_DXFER_TO_DEV, data, &data_size, sense, &sense_len);
	if(res){
		printf("SCSI_IO failed\n");
		return -1;
	}
	if(sense_len){
		print_sense_data(sense, sense_len);
		return -1;
	}

	return 0;
}

int scsi_persistent_reserve_out_preempt(int fd)
{
	unsigned char cdb[]={0x5f,0,0,0,0,0,0,0,0,0};

	unsigned int data_size=24;
	unsigned char data[data_size];

	unsigned int sense_len=32;
	unsigned char sense[sense_len];
	unsigned char service_action=4;
	int res;
	long long k;

	if (scope==-1) {
		printf("Must specify scope\n");
		printf("scsi_io --device=<DEVICE> --command=preempt --scope=<SCOPE> --type=<TYPE> --key=<KEY> --rmkey=<KEY>\n");
		_exit(10);
	}
	if (type==-1) {
		printf("Must specify type\n");
		printf("scsi_io --device=<DEVICE> --command=preempt --scope=<SCOPE> --type=<TYPE> --key=<KEY> --rmkey=<KEY>\n");
		_exit(10);
	}
	if (!key) {
		printf("Must specify key\n");
		printf("scsi_io --device=<DEVICE> --command=preempt --scope=<SCOPE> --type=<TYPE> --key=<KEY> --rmkey=<KEY>\n");
		_exit(10);
	}
	if (!rmkey) {
		printf("Must specify rmkey\n");
		printf("scsi_io --device=<DEVICE> --command=preempt --scope=<SCOPE> --type=<TYPE> --key=<KEY> --rmkey=<KEY>\n");
		_exit(10);
	}



	cdb[1]=service_action;
	cdb[2]=(scope<<4)|type;
	cdb[7]=(data_size>>8)&0xff;
	cdb[8]=data_size&0xff;

	memset(data, 0, data_size);

	/* Reservation Key */
	sscanf(key, "%llx", &k);
	data[0]=(k>>56)&0xff;
	data[1]=(k>>48)&0xff;
	data[2]=(k>>40)&0xff;
	data[3]=(k>>32)&0xff;
	data[4]=(k>>24)&0xff;
	data[5]=(k>>16)&0xff;
	data[6]=(k>> 8)&0xff;
	data[7]=(k    )&0xff;

	/* Service Action Key */
	sscanf(rmkey, "%llx", &k);
	data[8] =(k>>56)&0xff;
	data[9] =(k>>48)&0xff;
	data[10]=(k>>40)&0xff;
	data[11]=(k>>32)&0xff;
	data[12]=(k>>24)&0xff;
	data[13]=(k>>16)&0xff;
	data[14]=(k>> 8)&0xff;
	data[15]=(k    )&0xff;

	/* Spec_ip_ti=0 all_tg_pt=1 aptpl=0 */
	data[20]=0x04;

	printf("PERSISTENT RESERVE IN: RESERVE\n");

	res=scsi_io(fd, cdb, sizeof(cdb), SG_DXFER_TO_DEV, data, &data_size, sense, &sense_len);
	if(res){
		printf("SCSI_IO failed\n");
		return -1;
	}
	if(sense_len){
		print_sense_data(sense, sense_len);
		return -1;
	}

	return 0;
}

int scsi_persistent_reserve_out_register_and_ignore_existing_key(int fd)
{
	unsigned char cdb[]={0x5f,0,0,0,0,0,0,0,0,0};

	unsigned int data_size=24;
	unsigned char data[data_size];

	unsigned int sense_len=32;
	unsigned char sense[sense_len];
	unsigned char service_action=6;
	int res;
	long long k;

	if (scope==-1) {
		printf("Must specify scope\n");
		printf("scsi_io --device=<DEVICE> --command=registerkey --scope=<SCOPE> --type=<TYPE> --key=<KEY>\n");
		_exit(10);
	}
	if (type==-1) {
		printf("Must specify type\n");
		printf("scsi_io --device=<DEVICE> --command=registerkey --scope=<SCOPE> --type=<TYPE> --key=<KEY>\n");
		_exit(10);
	}
	if (!key) {
		printf("Must specify key\n");
		printf("scsi_io --device=<DEVICE> --command=registerkey --scope=<SCOPE> --type=<TYPE> --key=<KEY>\n");
		_exit(10);
	}

	sscanf(key, "%llx", &k);

	cdb[1]=service_action;
	cdb[2]=(scope<<4)|type;
	cdb[7]=(data_size>>8)&0xff;
	cdb[8]=data_size&0xff;

	memset(data, 0, data_size);

	/* Reservation Key */
	data[0]=0;
	data[1]=0;
	data[2]=0;
	data[3]=0;
	data[4]=0;
	data[5]=0;
	data[6]=0;
	data[7]=0;

	/* Service Action Key */
	data[8] =(k>>56)&0xff;
	data[9] =(k>>48)&0xff;
	data[10]=(k>>40)&0xff;
	data[11]=(k>>32)&0xff;
	data[12]=(k>>24)&0xff;
	data[13]=(k>>16)&0xff;
	data[14]=(k>> 8)&0xff;
	data[15]=(k    )&0xff;

	/* Spec_ip_ti=0 all_tg_pt=1 aptpl=0 */
	data[20]=0x04;

	printf("PERSISTENT RESERVE IN: REGISTER AND IGNORE EXISTING KEY\n");

	res=scsi_io(fd, cdb, sizeof(cdb), SG_DXFER_TO_DEV, data, &data_size, sense, &sense_len);
	if(res){
		printf("SCSI_IO failed\n");
		return -1;
	}
	if(sense_len){
		print_sense_data(sense, sense_len);
		return -1;
	}

	return 0;
}

int scsi_persistent_reserve_out_unregister_key(int fd)
{
	unsigned char cdb[]={0x5f,0,0,0,0,0,0,0,0,0};

	unsigned int data_size=24;
	unsigned char data[data_size];

	unsigned int sense_len=32;
	unsigned char sense[sense_len];
	unsigned char service_action=6;
	int res;
	long long k;

	if (scope==-1) {
		printf("Must specify scope\n");
		printf("scsi_io --device=<DEVICE> --command=unregisterkey --scope=<SCOPE> --type=<TYPE> --key=<KEY>\n");
		_exit(10);
	}
	if (type==-1) {
		printf("Must specify type\n");
		printf("scsi_io --device=<DEVICE> --command=unregisterkey --scope=<SCOPE> --type=<TYPE> --key=<KEY>\n");
		_exit(10);
	}
	if (!key) {
		printf("Must specify key\n");
		printf("scsi_io --device=<DEVICE> --command=unregisterkey --scope=<SCOPE> --type=<TYPE> --key=<KEY>\n");
		_exit(10);
	}

	sscanf(key, "%llx", &k);

	cdb[1]=service_action;
	cdb[2]=(scope<<4)|type;
	cdb[7]=(data_size>>8)&0xff;
	cdb[8]=data_size&0xff;

	memset(data, 0, data_size);

	/* Reservation Key */
	data[0]=(k>>56)&0xff;
	data[1]=(k>>48)&0xff;
	data[2]=(k>>40)&0xff;
	data[3]=(k>>32)&0xff;
	data[4]=(k>>24)&0xff;
	data[5]=(k>>16)&0xff;
	data[6]=(k>> 8)&0xff;
	data[7]=(k    )&0xff;

	/* Service Action Key */
	data[8]=0;
	data[9]=0;
	data[10]=0;
	data[11]=0;
	data[12]=0;
	data[13]=0;
	data[14]=0;
	data[15]=0;

	/* Spec_ip_ti=0 all_tg_pt=1 aptpl=0 */
	data[20]=0x04;

	printf("PERSISTENT RESERVE IN: UNREGISTER KEY\n");

	res=scsi_io(fd, cdb, sizeof(cdb), SG_DXFER_TO_DEV, data, &data_size, sense, &sense_len);
	if(res){
		printf("SCSI_IO failed\n");
		return -1;
	}
	if(sense_len){
		print_sense_data(sense, sense_len);
		return -1;
	}

	return 0;
}




int open_scsi_device(const char *dev)
{
	int fd, vers;

	if((fd=open(dev, O_RDWR))<0){
		printf("ERROR could not open device %s\n", dev);
		return -1;
	}
	if ((ioctl(fd, SG_GET_VERSION_NUM, &vers) < 0) || (vers < 30000)) {
		printf("/dev is not an sg device, or old sg driver\n");
		close(fd);
		return -1;
	}

	return fd;
}

typedef int (*scsi_func_t)(int fd);
typedef struct _cmds_t {
	const char *cmd;
	scsi_func_t func;
	const char *comment;
} cmds_t;
cmds_t cmds[] = {
	{"inq",		scsi_inquiry,	"Standard INQUIRY output"},
	{"vpd",		scsi_inquiry_supported_vpd_pages,	"Supported VPD Pages"},
	{"usn",		scsi_inquiry_unit_serial_number,	"Unit serial number"},
	{"readkeys",	scsi_persistent_reserve_in_read_keys,	"Read SCSI Reservation Keys"},
	{"readrsvr",	scsi_persistent_reserve_in_read_reservation, "Read SCSI Reservation Data"},
	{"reportcap",	scsi_persistent_reserve_in_report_capabilities, "Report reservation Capabilities"},
	{"registerkey",	scsi_persistent_reserve_out_register_and_ignore_existing_key,	"Register and ignore existing key"},
	{"unregisterkey", scsi_persistent_reserve_out_unregister_key, "Unregister a key"},
	{"clear",	scsi_persistent_reserve_out_clear, "Clear all reservations and registrations"},
	{"reserve",	scsi_persistent_reserve_out_reserve, "Reserve"},
	{"preempt",	scsi_persistent_reserve_out_preempt, "Preempt (remove someone elses registration)"},
};

void usage(void)
{
	int i;
	printf("Usage:  scsi_io --command <command> --device <device>\n");
	printf("Commands:\n");
	for (i=0;i<sizeof(cmds)/sizeof(cmds[0]);i++){
		printf("	%s	%s\n", cmds[i].cmd, cmds[i].comment);
	}	
}


int main(int argc, const char *argv[])
{
	int i, fd;
	int opt;
	scsi_func_t func=NULL;
	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		{ "scope", 's', POPT_ARG_INT, &scope, 0, "scope", "integer" },
		{ "type", 't', POPT_ARG_INT, &type, 0, "type", "integer" },
		{ "key",      'k', POPT_ARG_STRING, &key, 0, "key", "key" },
		{ "rmkey",      'r', POPT_ARG_STRING, &rmkey, 0, "rmkey", "rmkey" },
		{ "command",      'c', POPT_ARG_STRING, &command, 0, "command", "command" },
		{ "device",      'd', POPT_ARG_STRING, &device, 0, "device", "device" },
//		{ "machinereadable", 'Y', POPT_ARG_NONE, &options.machinereadable, 0, "enable machinereadable output", NULL },
		POPT_TABLEEND
	};
	poptContext pc;

	pc = poptGetContext(argv[0], argc, argv, popt_options, POPT_CONTEXT_KEEP_FIRST);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		default:
			fprintf(stderr, "Invalid option %s: %s\n", 
				poptBadOption(pc, 0), poptStrerror(opt));
			_exit(1);
		}
	}

	if (!command) {
		printf("Must specify the command\n");
		usage();
		_exit(10);
	}

	if (!device) {
		printf("Must specify the device\n");
		usage();
		_exit(10);
	}

	fd=open_scsi_device(device);
	if(fd<0){
		printf("Could not open SCSI device %s\n",device);
		usage();
		_exit(10);
	}

	for (i=0;i<sizeof(cmds)/sizeof(cmds[0]);i++){
		if(!strcmp(cmds[i].cmd, command)) {
			func = cmds[i].func;
			break;
		}		
	}
	if (!func) {
		printf("Unrecognized command : %s\n", command);
		usage();
		_exit(10);
	}

	func(fd);

#if 0
	scsi_persistent_reserve_in_read_full_status(fd);
	scsi_persistent_reserve_out_register_and_ignore_existing_key(fd);
	scsi_persistent_reserve_in_read_keys(fd);

	scsi_persistent_reserve_out_reserve(fd);
	scsi_persistent_reserve_in_read_reservation(fd);

	scsi_persistent_reserve_out_clear(fd);
	scsi_persistent_reserve_in_read_reservation(fd);

	scsi_persistent_reserve_out_unregister_key(fd);
	scsi_persistent_reserve_in_read_keys(fd);
#endif
	return 0;
}
