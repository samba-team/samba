/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Guenther Deschner                  2009.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "../librpc/gen_ndr/ndr_spoolss.h"
#include "rpc_client/init_spoolss.h"

/*******************************************************************
********************************************************************/

bool init_systemtime(struct spoolss_Time *r,
		     struct tm *unixtime)
{
	if (!r || !unixtime) {
		return false;
	}

	r->year		= unixtime->tm_year+1900;
	r->month	= unixtime->tm_mon+1;
	r->day_of_week	= unixtime->tm_wday;
	r->day		= unixtime->tm_mday;
	r->hour		= unixtime->tm_hour;
	r->minute	= unixtime->tm_min;
	r->second	= unixtime->tm_sec;
	r->millisecond	= 0;

	return true;
}

time_t spoolss_Time_to_time_t(const struct spoolss_Time *r)
{
	struct tm unixtime;

	unixtime.tm_year	= r->year - 1900;
	unixtime.tm_mon		= r->month - 1;
	unixtime.tm_wday	= r->day_of_week;
	unixtime.tm_mday	= r->day;
	unixtime.tm_hour	= r->hour;
	unixtime.tm_min		= r->minute;
	unixtime.tm_sec		= r->second;

	return mktime(&unixtime);
}

/*******************************************************************
 ********************************************************************/

WERROR pull_spoolss_PrinterData(TALLOC_CTX *mem_ctx,
				const DATA_BLOB *blob,
				union spoolss_PrinterData *data,
				enum winreg_Type type)
{
	enum ndr_err_code ndr_err;
	ndr_err = ndr_pull_union_blob(blob, mem_ctx, data, type,
			(ndr_pull_flags_fn_t)ndr_pull_spoolss_PrinterData);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_GENERAL_FAILURE;
	}
	return WERR_OK;
}

/*******************************************************************
 ********************************************************************/

WERROR push_spoolss_PrinterData(TALLOC_CTX *mem_ctx, DATA_BLOB *blob,
				enum winreg_Type type,
				union spoolss_PrinterData *data)
{
	enum ndr_err_code ndr_err;
	ndr_err = ndr_push_union_blob(blob, mem_ctx, data, type,
			(ndr_push_flags_fn_t)ndr_push_spoolss_PrinterData);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_GENERAL_FAILURE;
	}
	return WERR_OK;
}

/*******************************************************************
 ********************************************************************/

void spoolss_printerinfo2_to_setprinterinfo2(const struct spoolss_PrinterInfo2 *i,
					     struct spoolss_SetPrinterInfo2 *s)
{
	s->servername		= i->servername;
	s->printername		= i->printername;
	s->sharename		= i->sharename;
	s->portname		= i->portname;
	s->drivername		= i->drivername;
	s->comment		= i->comment;
	s->location		= i->location;
	s->devmode_ptr		= 0;
	s->sepfile		= i->sepfile;
	s->printprocessor	= i->printprocessor;
	s->datatype		= i->datatype;
	s->parameters		= i->parameters;
	s->secdesc_ptr		= 0;
	s->attributes		= i->attributes;
	s->priority		= i->priority;
	s->defaultpriority	= i->defaultpriority;
	s->starttime		= i->starttime;
	s->untiltime		= i->untiltime;
	s->status		= i->status;
	s->cjobs		= i->cjobs;
	s->averageppm		= i->averageppm;
}

/****************************************************************************
****************************************************************************/

bool driver_info_ctr_to_info8(struct spoolss_AddDriverInfoCtr *r,
			      struct spoolss_DriverInfo8 *_info8)
{
	struct spoolss_DriverInfo8 info8;

	ZERO_STRUCT(info8);

	switch (r->level) {
	case 3:
		info8.version		= r->info.info3->version;
		info8.driver_name	= r->info.info3->driver_name;
		info8.architecture	= r->info.info3->architecture;
		info8.driver_path	= r->info.info3->driver_path;
		info8.data_file		= r->info.info3->data_file;
		info8.config_file	= r->info.info3->config_file;
		info8.help_file		= r->info.info3->help_file;
		info8.monitor_name	= r->info.info3->monitor_name;
		info8.default_datatype	= r->info.info3->default_datatype;
		if (r->info.info3->dependent_files && r->info.info3->dependent_files->string) {
			info8.dependent_files	= r->info.info3->dependent_files->string;
		}
		break;
	case 6:
		info8.version		= r->info.info6->version;
		info8.driver_name	= r->info.info6->driver_name;
		info8.architecture	= r->info.info6->architecture;
		info8.driver_path	= r->info.info6->driver_path;
		info8.data_file		= r->info.info6->data_file;
		info8.config_file	= r->info.info6->config_file;
		info8.help_file		= r->info.info6->help_file;
		info8.monitor_name	= r->info.info6->monitor_name;
		info8.default_datatype	= r->info.info6->default_datatype;
		if (r->info.info6->dependent_files && r->info.info6->dependent_files->string) {
			info8.dependent_files	= r->info.info6->dependent_files->string;
		}
		info8.driver_date	= r->info.info6->driver_date;
		info8.driver_version	= r->info.info6->driver_version;
		info8.manufacturer_name = r->info.info6->manufacturer_name;
		info8.manufacturer_url	= r->info.info6->manufacturer_url;
		info8.hardware_id	= r->info.info6->hardware_id;
		info8.provider		= r->info.info6->provider;
		break;
	case 8:
		info8.version		= r->info.info8->version;
		info8.driver_name	= r->info.info8->driver_name;
		info8.architecture	= r->info.info8->architecture;
		info8.driver_path	= r->info.info8->driver_path;
		info8.data_file		= r->info.info8->data_file;
		info8.config_file	= r->info.info8->config_file;
		info8.help_file		= r->info.info8->help_file;
		info8.monitor_name	= r->info.info8->monitor_name;
		info8.default_datatype	= r->info.info8->default_datatype;
		if (r->info.info8->dependent_files && r->info.info8->dependent_files->string) {
			info8.dependent_files	= r->info.info8->dependent_files->string;
		}
		if (r->info.info8->previous_names && r->info.info8->previous_names->string) {
			info8.previous_names	= r->info.info8->previous_names->string;
		}
		info8.driver_date	= r->info.info8->driver_date;
		info8.driver_version	= r->info.info8->driver_version;
		info8.manufacturer_name = r->info.info8->manufacturer_name;
		info8.manufacturer_url	= r->info.info8->manufacturer_url;
		info8.hardware_id	= r->info.info8->hardware_id;
		info8.provider		= r->info.info8->provider;
		info8.print_processor	= r->info.info8->print_processor;
		info8.vendor_setup	= r->info.info8->vendor_setup;
		if (r->info.info8->color_profiles && r->info.info8->color_profiles->string) {
			info8.color_profiles = r->info.info8->color_profiles->string;
		}
		info8.inf_path		= r->info.info8->inf_path;
		info8.printer_driver_attributes = r->info.info8->printer_driver_attributes;
		if (r->info.info8->core_driver_dependencies && r->info.info8->core_driver_dependencies->string) {
			info8.core_driver_dependencies = r->info.info8->core_driver_dependencies->string;
		}
		info8.min_inbox_driver_ver_date = r->info.info8->min_inbox_driver_ver_date;
		info8.min_inbox_driver_ver_version = r->info.info8->min_inbox_driver_ver_version;
		break;
	default:
		return false;
	}

	*_info8 = info8;

	return true;
}
