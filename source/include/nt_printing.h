typedef struct nt_printer_driver_info_level_3
{
	uint32 cversion;

	fstring name;
	fstring environment;
	fstring driverpath;
	fstring datafile;
	fstring configfile;
	fstring helpfile;
	fstring monitorname;
	fstring defaultdatatype;
	char    **dependentfiles;

} NT_PRINTER_DRIVER_INFO_LEVEL_3;

typedef struct nt_printer_driver_info_level
{
	NT_PRINTER_DRIVER_INFO_LEVEL_3 *info_3;
} NT_PRINTER_DRIVER_INFO_LEVEL;

typedef struct nt_printer_param
{
	fstring value;
	uint32 type;
	uint8 *data;
	int data_len;
	struct nt_printer_param *next;
} NT_PRINTER_PARAM;

typedef struct ntdevicemode
{
	fstring	devicename;
	uint16	specversion;
	uint16	driverversion;
	uint16	size;
	uint16	driverextra;
	uint32	fields;
	uint16	orientation;
	uint16	papersize;
	uint16	paperlength;
	uint16	paperwidth;
	uint16	scale;
	uint16	copies;
	uint16	defaultsource;
	uint16	printquality;
	uint16	color;
	uint16	duplex;
	uint16	yresolution;
	uint16	ttoption;
	uint16	collate;
	fstring	formname;
	uint16	logpixels;
	uint32	bitsperpel;
	uint32	pelswidth;
	uint32	pelsheight;
	uint32	displayflags;
	uint32	displayfrequency;
	uint32	icmmethod;
	uint32	icmintent;
	uint32	mediatype;
	uint32	dithertype;
	uint32	reserved1;
	uint32	reserved2;
	uint32	panningwidth;
	uint32	panningheight;
	uint8 	*private;
} NT_DEVICEMODE; 

typedef struct nt_printer_info_level_2
{
	uint32 attributes;
	uint32 priority;
	uint32 default_priority;
	uint32 starttime;
	uint32 untiltime;
	uint32 status;
	uint32 cjobs;
	uint32 averageppm;
	fstring servername;
	fstring printername;
	fstring sharename;
	fstring portname;
	fstring drivername;
	fstring comment;
	fstring location;
	NT_DEVICEMODE *devmode;
	fstring sepfile;
	fstring printprocessor;
	fstring datatype;
	fstring parameters;
	NT_PRINTER_PARAM *specific;
	/* SEC_DESC_BUF *secdesc; */
	/* not used but ... and how ??? */
} NT_PRINTER_INFO_LEVEL_2;

typedef struct nt_printer_info_level
{
	NT_PRINTER_INFO_LEVEL_2 *info_2;
} NT_PRINTER_INFO_LEVEL;


