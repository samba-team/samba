#ifndef _PRINTERDB_H_
#define _PRINTERDB_H_
/* 
   Unix SMB/CIFS implementation.

   PrinterDB headers

   Copyright (C) Guenther Deschner 2004
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the
   Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA  02111-1307, USA.   
*/

#define SMB_PRINTERDB_INTERFACE_VERSION	1

/* TODO: 
 * use WERROR as general return code 
 * add a mem_ctx
 * discuss with jerry and vl
 */

enum tdb_files {
	TDB_DRIVERS,
	TDB_FORMS,
	TDB_PRINTERS,
	TDB_SECDESC,
	TDB_DRIVERSINIT
};

/* Filled out by PRINTDB backends */
struct printerdb_methods {

	time_t (*get_last_update) (int tdb);
	BOOL (*set_last_update) (time_t update, int tdb);

	/* Called when backend is first loaded */
	BOOL (*init)( char *params );

	uint32 (*get_c_setprinter) ( void );
	uint32 (*update_c_setprinter)( BOOL initialize );

	int (*get_forms)( nt_forms_struct **list );
	int (*write_forms)( nt_forms_struct **list, int number );
	BOOL (*del_form)( char *del_name, WERROR *ret );

	int (*get_drivers)( fstring **list, const char *short_archi, uint32 version );
	uint32 (*add_driver)( NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver, const char *short_archi );
	WERROR (*get_driver)( NT_PRINTER_DRIVER_INFO_LEVEL_3 **driver, fstring drivername, const char *arch, uint32 version);
	BOOL (*del_driver)( const char *short_archi, int version, const char *drivername );
	BOOL (*del_driver_init) (const char *drivername);

	int (*get_printers)(fstring **list);
	WERROR (*get_printer)(NT_PRINTER_INFO_LEVEL_2 **info_ptr, const char *sharename);
	WERROR (*update_printer)(NT_PRINTER_INFO_LEVEL_2 *info);
	WERROR (*del_printer)( const char *sharename );

	WERROR (*get_secdesc)( TALLOC_CTX *mem_ctx, const char *printername, SEC_DESC_BUF **secdesc_ctr );
	WERROR (*set_secdesc)( TALLOC_CTX *mem_ctx, const char *printername, SEC_DESC_BUF *secdesc_ctr );

	BOOL (*set_driver_init)( NT_PRINTER_INFO_LEVEL_2 *driver );
	BOOL (*get_driver_init)( NT_PRINTER_INFO_LEVEL_2 **driver );
	uint32 (*update_driver_init)(NT_PRINTER_INFO_LEVEL_2 *info);
	/* Called when backend is unloaded */
	BOOL (*close)(void);

	/* Called to dump backend status */
	void (*status)(void);
};
#endif /* _PRINTERDB_H_ */
