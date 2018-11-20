/*
   Unix SMB/CIFS implementation.

   Copyright (C) Guenther Deschner 2016

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "librpc/gen_ndr/ndr_spoolss.h"
#include "rpc_client/init_spoolss.h"
#include "libgpo/gpo_ini.h"
#include "printer_driver.h"

#define ADD_TO_ARRAY(mem_ctx, type, elem, array, num) \
do { \
	*(array) = talloc_realloc(mem_ctx, (*(array)), type, (*(num))+1); \
	SMB_ASSERT((*(array)) != NULL); \
	(*(array))[*(num)] = (elem); \
	(*(num)) += 1; \
} while (0)


/* GetPrinterDriverDirectory  -> drivers and dependent files */
#define PRINTER_INF_DIRID_66000

/* GetPrintProcessorDirectory -> print processors */
#define PRINTER_INF_DIRID_66001

/* GetColorDirectory -> color profiles */
#define PRINTER_INF_DIRID_66003

static const char *get_string_unquote(const char *s)
{
	bool ok;
	size_t len;

	if (s == NULL) {
		return NULL;
	}

	len = strlen(s);
	if (len < 2) {
		return s;
	}

	if (s[0] == '"' && s[len-1] == '"') {
		ok = trim_string(discard_const(s), "\"", "\"");
		if (!ok) {
			return NULL;
		}
	}

	return s;
}

/*
 * '%STRING%' indicates STRING is localized in the [Strings] section
 */

static const char *get_string_token(struct gp_inifile_context *ctx,
				    const char *s)
{
	NTSTATUS status;
	bool ok;
	char *key;
	const char *s2;

	if (s != NULL &&  s[0] != '%' && s[strlen(s)-1] != '%') {
		return s;
	}

	ok = trim_string(discard_const(s), "%", "%");
	if (!ok) {
		return NULL;
	}

	key = talloc_asprintf(ctx, "Strings:%s", s);
	if (key == NULL) {
		return NULL;
	}

	status = gp_inifile_getstring(ctx, key, &s2);
	talloc_free(key);
	if (!NT_STATUS_IS_OK(status)) {
		/* what can you do... */
		return s;
	}

	return s2;
}

static NTSTATUS gp_inifile_getstring_ext(struct gp_inifile_context *ctx,
					 const char *key,
					 const char **ret)
{
	NTSTATUS status;
	const char *s;

	status = gp_inifile_getstring(ctx, key, &s);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	s = get_string_unquote(s);
	if (s == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (s[0] == '%' && s[strlen(s)-1] == '%') {
		s = get_string_token(ctx, s);
	}

	s = get_string_unquote(s);
	if (s == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	*ret = s;

	return NT_STATUS_OK;
}

static NTSTATUS find_manufacturer_name(struct gp_inifile_context *ctx,
				       TALLOC_CTX *mem_ctx,
				       const char *section_name,
				       const char **manufacturer_name)
{
	NTSTATUS status;
	size_t num_keys = 0;
	const char **keys = NULL;
	const char **values = NULL;
	const char *s;
	char *p;

	status = gp_inifile_enum_section(ctx, section_name, &num_keys, &keys, &values);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (num_keys < 1) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	s = talloc_strdup(mem_ctx, keys[0]);
	if (s == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	p = strchr(s, ':');
	if (p == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	*p = '\0';
	p++;

	s = get_string_unquote(p);
	if (s == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	s = get_string_token(ctx, s);

	s = get_string_unquote(s);
	if (s == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (s != NULL) {
		*manufacturer_name = talloc_strdup(mem_ctx, s);
		if (*manufacturer_name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	talloc_free(keys);
	talloc_free(values);

	return NT_STATUS_OK;
}

static NTSTATUS find_manufacturer_url(struct gp_inifile_context *ctx,
				      TALLOC_CTX *mem_ctx,
				      const char *section_name,
				      const char *manufacturer_name,
				      const char **manufacturer_url)
{
	NTSTATUS status;
	size_t num_keys = 0;
	const char **keys = NULL;
	const char **values = NULL;
	const char *s;
	char *p;

	status = gp_inifile_enum_section(ctx, section_name, &num_keys, &keys, &values);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (num_keys < 1) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	p = strchr(keys[0], ':');
	if (p == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	*p = '\0';
	p++;

	s = get_string_unquote(p);
	if (s == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	s = get_string_token(ctx, s);

	s = get_string_unquote(s);
	if (s == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (strequal(s, manufacturer_name)) {
		s = get_string_unquote(values[0]);
		if (s == NULL) {
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	if (s != NULL) {
		*manufacturer_url = talloc_strdup(mem_ctx, s);
		if (*manufacturer_url == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	talloc_free(keys);
	talloc_free(values);

	return NT_STATUS_OK;
}

static NTSTATUS add_string_to_spoolss_array(TALLOC_CTX *mem_ctx,
					    const char *s,
					    struct spoolss_StringArray **r)
{
	size_t count = 2;
	struct spoolss_StringArray *a = *r;
	bool ok;
	int i;

	if (a == NULL) {
		a = talloc_zero(mem_ctx, struct spoolss_StringArray);
		if (a == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (a->string == NULL) {
		a->string = talloc_zero_array(a, const char *, count);
		if (a->string == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	for (i = 0; a->string[i] != NULL; i++) { ;; }
	count = i;

	ok = add_string_to_array(mem_ctx, s, &a->string, &count);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	a->string = talloc_realloc(mem_ctx, a->string, const char *, count + 1);
	if (a->string == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	a->string[count] = NULL;

	*r = a;

	return NT_STATUS_OK;
}

static NTSTATUS add_dependent_driver_file(TALLOC_CTX *mem_ctx,
					  const char *file,
					  struct spoolss_StringArray **r)
{
	char *p;

	if (file == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (file[0] == '@') {
		file++;
	}

	p = strchr(file, ',');
	if (p != NULL) {
		*p = '\0';
	}

	return add_string_to_spoolss_array(mem_ctx, file, r);
}

/*
 * https://msdn.microsoft.com/de-de/windows/hardware/drivers/install/inf-manufacturer-section
 *
 * [Manufacturer]
 * "Kyocera"=Kyocera,NTx86.5.1,NTx86.6.0,NTamd64.5.1,NTamd64.6.0
 */

static NTSTATUS enum_devices_in_toc(struct gp_inifile_context *ctx,
				    TALLOC_CTX *mem_ctx,
				    size_t *pnum_devices,
				    const char ***pdevices,
				    const char ***pdevice_values)
{
	NTSTATUS status;
	size_t num_manufacturers = 0;
	const char **manufacturers = NULL;
	const char **values = NULL;
	char *p;
	int i;
	bool ok;

	status = gp_inifile_enum_section(ctx, "Manufacturer", &num_manufacturers, &manufacturers, &values);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	for (i = 0; i < num_manufacturers; i++) {

		const char *models_section_name;
		const char *s;
		char **decorations;
		int j;

		DEBUG(11,("processing manufacturer: %s\n", manufacturers[i]));

		status = gp_inifile_getstring(ctx, manufacturers[i], &s);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		decorations = str_list_make_v3(mem_ctx, s, ",");
		if (decorations == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		models_section_name = decorations[0];

		for (j = 1; decorations[j] != NULL; j++) {

			/*
			 * https://msdn.microsoft.com/de-de/windows/hardware/drivers/install/inf-models-section
			 */

			const char *decorated_models_section_name;
			size_t num_devices = 0;
			const char **devices = NULL;
			const char **device_values = NULL;
			int d;
			size_t c = 0;

			decorated_models_section_name = talloc_asprintf(mem_ctx, "%s.%s",
									models_section_name,
									decorations[j]);
			if (decorated_models_section_name == NULL) {
				return NT_STATUS_NO_MEMORY;
			}

			DEBUG(11,("processing decorated models_section_name: %s\n",
				decorated_models_section_name));

			status = gp_inifile_enum_section(ctx, decorated_models_section_name,
							 &num_devices, &devices,
							 &device_values);
			for (d = 0; d < num_devices; d++) {

				DEBUG(11,("processing device: %s\n",
					devices[d]));

				s = talloc_strdup(mem_ctx, devices[d]);
				if (s == NULL) {
					return NT_STATUS_NO_MEMORY;
				}

				p = strchr(s, ':');
				if (p == NULL) {
					return NT_STATUS_DRIVER_INTERNAL_ERROR;
				}

				*p = '\0';
				p++;

				s = get_string_unquote(p);

				ok = add_string_to_array(mem_ctx, s, pdevices, pnum_devices);
				if (!ok) {
					return NT_STATUS_NO_MEMORY;
				}
				ok = add_string_to_array(mem_ctx, device_values[d], pdevice_values, &c);
				if (!ok) {
					return NT_STATUS_NO_MEMORY;
				}
			}
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS find_device_in_toc(struct gp_inifile_context *ctx,
				   TALLOC_CTX *mem_ctx,
				   const char *device_description,
				   const char **value)
{
	NTSTATUS status;
	size_t num_devices = 0;
	const char **devices = NULL;
	const char **device_values = NULL;
	int d;

	if (device_description == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = enum_devices_in_toc(ctx, mem_ctx,
				     &num_devices,
				     &devices,
				     &device_values);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	for (d = 0; d < num_devices; d++) {

		if (strequal(device_description, devices[d])) {

			DEBUG(10,("found device_description: %s\n",
				device_description));

			*value = talloc_strdup(mem_ctx, device_values[d]);
			if (*value == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			DEBUGADD(10,("and returned: %s\n", *value));

			return NT_STATUS_OK;
		}
	}

	return NT_STATUS_DRIVER_INTERNAL_ERROR;
}

/*
 * https://msdn.microsoft.com/de-de/windows/hardware/drivers/install/inf-copyfiles-directive
 */

static NTSTATUS process_driver_section_copyfiles(struct gp_inifile_context *ctx,
						 TALLOC_CTX *mem_ctx,
						 const char *driver_section,
						 struct spoolss_AddDriverInfo8 *r)
{
	NTSTATUS status;
	size_t num_keys = 0;
	char *p, *key;
	const char **keys = NULL;
	const char **values = NULL;
	int i;
	char *str;
	const char *s;

	key = talloc_asprintf(mem_ctx, "%s:%s", driver_section, "CopyFiles");
	if (key == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(10,("Checking for CopyFiles entry in %s\n", driver_section));

	status = gp_inifile_getstring(ctx, key, &s);
	if (!NT_STATUS_IS_OK(status)) {
		return NT_STATUS_OK;
	}

	DEBUG(10,("these are the files to copy: %s\n", s));

	while (next_token_talloc(mem_ctx, &s, &str, ",")) {

		DEBUG(10,("trying section: %s\n", str));

		if (str[0] == '@') {
			DEBUG(10,("adding dependent driver file: %s\n", str));
			status = add_dependent_driver_file(mem_ctx, str, &r->dependent_files);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			continue;
		}

		status = gp_inifile_enum_section(ctx, str, &num_keys, &keys, &values);
		if (NT_STATUS_IS_OK(status)) {
			for (i = 0; i < num_keys; i++) {
				p = strchr(keys[i], ':');
				if (p == NULL) {
					return NT_STATUS_INVALID_PARAMETER;
				}
				*p = '\0';
				p++;

				DEBUG(10,("adding dependent driver file: %s\n", p));

				status = add_dependent_driver_file(mem_ctx, p, &r->dependent_files);
				if (!NT_STATUS_IS_OK(status)) {
					return status;
				}
			}
			TALLOC_FREE(keys);
			TALLOC_FREE(values);
		}
	}

	return NT_STATUS_OK;
}

#define process_driver_section_val(_ctx, _mem_ctx, _section, _r, _key, _element) \
do { \
	NTSTATUS _status; \
	const char *__key, *_s; \
	__key = talloc_asprintf(_mem_ctx, "%s:%s", _section, _key); \
	NT_STATUS_HAVE_NO_MEMORY(__key); \
	_status = gp_inifile_getstring(_ctx, __key, &_s); \
	if (NT_STATUS_IS_OK(_status)) { \
		(_r)->_element = talloc_strdup(mem_ctx, _s); \
		NT_STATUS_HAVE_NO_MEMORY((_r)->_element); \
	} \
} while(0);

static NTSTATUS process_driver_section_colorprofiles(struct gp_inifile_context *ctx,
						     TALLOC_CTX *mem_ctx,
						     const char *section,
						     struct spoolss_AddDriverInfo8 *r)
{
	NTSTATUS status;
	const char *key, *s;

	key = talloc_asprintf(mem_ctx, "%s:%s", section, "ColorProfiles");
	if (key == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = gp_inifile_getstring_ext(ctx, key, &s);
	if (NT_STATUS_IS_OK(status)) {

		status = add_string_to_spoolss_array(mem_ctx, s, &r->color_profiles);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS process_driver_section_printprocessor(struct gp_inifile_context *ctx,
						      TALLOC_CTX *mem_ctx,
						      const char *section,
						      struct spoolss_AddDriverInfo8 *r)
{
	NTSTATUS status;
	char *key, *p;
	const char *s;

	key = talloc_asprintf(mem_ctx, "%s:%s", section, "PrintProcessor");
	if (key == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = gp_inifile_getstring_ext(ctx, key, &s);
	if (NT_STATUS_IS_OK(status)) {
		s = get_string_unquote(s);

		p = strchr(s, ',');
		if (p == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		*p = '\0';
		r->print_processor = talloc_strdup(mem_ctx, s);
		if (r->print_processor == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS process_driver_section_data_section(struct gp_inifile_context *ctx,
						    TALLOC_CTX *mem_ctx,
						    const char *section,
						    struct spoolss_AddDriverInfo8 *r)
{
	NTSTATUS status;
	char *key;
	const char *s;

	key = talloc_asprintf(mem_ctx, "%s:%s", section, "DataSection");
	if (key == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = gp_inifile_getstring(ctx, key, &s);
	if (NT_STATUS_IS_OK(status)) {
		process_driver_section_val(ctx, mem_ctx, s, r,
					   "DriverFile", driver_path);
		process_driver_section_val(ctx, mem_ctx, s, r,
					   "HelpFile", help_file);
		process_driver_section_val(ctx, mem_ctx, s, r,
					   "DataFile", data_file);
		process_driver_section_val(ctx, mem_ctx, s, r,
					   "ConfigFile", config_file);
	}

	return NT_STATUS_OK;
}


static NTSTATUS process_one_core_driver_section(struct gp_inifile_context *core_ctx,
						TALLOC_CTX *mem_ctx,
						const char *driver_section,
						struct spoolss_AddDriverInfo8 *r)
{
	NTSTATUS status;
	size_t num_keys = 0;
	const char **keys = NULL;
	const char **values = NULL;
	int i;

	DEBUG(10,("CoreDriverSection is: %s\n", driver_section));

	status = gp_inifile_enum_section(core_ctx, driver_section, &num_keys, &keys, &values);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	for (i = 0; i < num_keys; i++) {

		status = process_driver_section_copyfiles(core_ctx, mem_ctx, driver_section, r);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		process_driver_section_val(core_ctx, mem_ctx, driver_section, r,
					   "DriverFile", driver_path);
		process_driver_section_val(core_ctx, mem_ctx, driver_section, r,
					   "HelpFile", help_file);
		process_driver_section_val(core_ctx, mem_ctx, driver_section, r,
					   "ConfigFile", config_file);

		status = process_driver_section_colorprofiles(core_ctx, mem_ctx, driver_section, r);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	talloc_free(keys);
	talloc_free(values);

	return NT_STATUS_OK;
}

/*
 * CoreDriverSections="{D20EA372-DD35-4950-9ED8-A6335AFE79F0},UNIDRV_BIDI.OEM,UNIDRV_BIDI_DATA","{D20EA372-DD35-4950-9ED8-A6335AFE79F2},PCLXL.OEM","{D20EA372-DD35-4950-9ED8-A6335AFE79F3},sRGBPROFILE.OEM"
 */
static NTSTATUS process_core_driver_sections(struct gp_inifile_context *core_ctx,
					     TALLOC_CTX *mem_ctx,
					     const char *value,
					     struct spoolss_AddDriverInfo8 *r)
{
	NTSTATUS status;
	char *p;
	char **list;
	int i;

	list = str_list_make_v3(mem_ctx, value, ",");
	if (list == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; list[i] != NULL; i++) {
		char **array;
		int a;

		/* FIXME: do we have to validate the core driver guid ? */

		p = strchr(list[i], ',');
		if (p != NULL) {
			*p = '\0';
			p++;
		}

		DEBUG(10,("CoreDriverSections we have to process: %s\n", p));

		array = str_list_make_v3(mem_ctx, p, ",");
		if (array == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		for (a = 0; array[a] != NULL; a++) {

			if (core_ctx == NULL) {
				DEBUG(0,("Need to process CoreDriverSections but "
					"have no Core Driver Context!\n"));
				return NT_STATUS_DRIVER_INTERNAL_ERROR;
			}

			status = process_one_core_driver_section(core_ctx, mem_ctx, array[a], r);
			if (!NT_STATUS_IS_OK(status)) {
				continue;
			}
		}
	}

	return NT_STATUS_OK;
}

/*
 * https://msdn.microsoft.com/de-de/windows/hardware/drivers/install/inf-ddinstall-section
 */
static NTSTATUS find_driver_files(struct gp_inifile_context *ctx,
				  struct gp_inifile_context *core_ctx,
				  TALLOC_CTX *mem_ctx,
				  const char *driver_name,
				  struct spoolss_AddDriverInfo8 *r)
{
	NTSTATUS status;
	char *key;
	const char *s;
	const char *value;
	char *install_section_name;
	bool ok;
	char *hw_id;

	status = find_device_in_toc(ctx, mem_ctx, driver_name, &value);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	r->driver_name = talloc_strdup(mem_ctx, driver_name);
	if (r->driver_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ok = next_token_talloc(mem_ctx, &value, &install_section_name, ",");
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(10,("driver_name: %s, value: %s, install_section_name: %s\n",
		driver_name, value, install_section_name));

	/* Hardware Id is optional */
	ok = next_token_talloc(mem_ctx, &value, &hw_id, ",");
	if (ok) {
		r->hardware_id = hw_id;
	}

	status = process_driver_section_copyfiles(ctx, mem_ctx, install_section_name, r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	process_driver_section_val(ctx, mem_ctx, install_section_name, r,
				   "DriverFile", driver_path);
	process_driver_section_val(ctx, mem_ctx, install_section_name, r,
				   "HelpFile", help_file);
	process_driver_section_val(ctx, mem_ctx, install_section_name, r,
				   "DataFile", data_file);
	process_driver_section_val(ctx, mem_ctx, install_section_name, r,
				   "ConfigFile", config_file);

	status = process_driver_section_printprocessor(ctx, mem_ctx, install_section_name, r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = process_driver_section_data_section(ctx, mem_ctx, install_section_name, r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	key = talloc_asprintf(mem_ctx, "%s:%s", install_section_name, "CoreDriverSections");
	if (key == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = gp_inifile_getstring(ctx, key, &s);
	if (NT_STATUS_IS_OK(status)) {

		DEBUG(10,("found CoreDriverSections: %s\n", s));

		status = process_core_driver_sections(core_ctx, mem_ctx, s, r);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}

struct inf_context {
	struct gp_inifile_context *ctx;
	struct gp_inifile_context *core_ctx;
};

static NTSTATUS init_inf_context(TALLOC_CTX *mem_ctx,
				 const char *inf_filename,
				 const char *core_filename,
				 struct inf_context **_inf_ctx)
{
	NTSTATUS status;
	struct gp_inifile_context *ctx;
	struct gp_inifile_context *core_ctx = NULL;
	struct inf_context *inf_ctx;

	inf_ctx = talloc_zero(mem_ctx, struct inf_context);
	if (inf_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = gp_inifile_init_context_direct(mem_ctx,
						inf_filename,
						&ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("init_inf_context: failed to load %s\n", inf_filename));
		return status;
	}

	if (ctx->generated_filename != NULL) {
		unlink(ctx->generated_filename);
	}

	if (core_filename != NULL) {
		status = gp_inifile_init_context_direct(mem_ctx,
							core_filename,
							&core_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10,("init_inf_context: failed to load %s\n", core_filename));
			return status;
		}

		if (core_ctx->generated_filename != NULL) {
			unlink(core_ctx->generated_filename);
		}
	}

	inf_ctx->ctx = ctx;
	inf_ctx->core_ctx = core_ctx;

	*_inf_ctx = inf_ctx;

	return NT_STATUS_OK;
}

static NTSTATUS process_driver_driverver(struct gp_inifile_context *ctx,
					 struct spoolss_AddDriverInfo8 *r)
{
	NTSTATUS status;
	const char *s;
	char *p;
	bool ok;
	const char *str;

	status = gp_inifile_getstring(ctx, "Version:DriverVer", &s);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	str = talloc_strdup(ctx, s);
	if (str == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	p = strchr(str, ',');
	if (p) {
		*p = '\0';
		p++;
	}

	ok = spoolss_timestr_to_NTTIME(str, &r->driver_date);
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ok = spoolss_driver_version_to_qword(p, &r->driver_version);
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

/*
 * Parse a SourceDisksNames section,
 * https://msdn.microsoft.com/de-de/windows/hardware/drivers/install/inf-sourcedisksnames-section?f=255&MSPPError=-2147217396
 */
static NTSTATUS process_source_disk_name(struct gp_inifile_context *ctx,
					 TALLOC_CTX *mem_ctx,
					 const char *short_environment,
					 const char **source_disk_name)
{
	NTSTATUS status;
	bool ok;
	const char *key;
	size_t num_keys = 0;
	const char **keys = NULL;
	const char **values = NULL;
	int i;

	key = talloc_asprintf(mem_ctx, "SourceDisksNames.%s", short_environment);
	if (key == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = gp_inifile_enum_section(ctx, key, &num_keys, &keys, &values);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (keys == NULL && values == NULL) {
		key = "SourceDisksNames";

		status = gp_inifile_enum_section(ctx, key, &num_keys, &keys, &values);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	for (i = 0; i < num_keys; i++) {

		/*
		 * 1   = %Disk1%,,,"Amd64"
		 * diskid = disk-description[,[tag-or-cab-file],[unused],[path],[flags][,tag-file]]
		 */
		char *disk_description, *tag_or_cab_file, *unused, *path;

		ok = next_token_no_ltrim_talloc(mem_ctx, &values[i], &disk_description, ",");
		if (!ok) {
			continue;
		}

		ok = next_token_no_ltrim_talloc(mem_ctx, &values[i], &tag_or_cab_file, ",");
		if (!ok) {
			continue;
		}

		ok = next_token_no_ltrim_talloc(mem_ctx, &values[i], &unused, ",");
		if (!ok) {
			continue;
		}

		ok = next_token_no_ltrim_talloc(mem_ctx, &values[i], &path, ",");
		if (!ok) {
			continue;
		}

		*source_disk_name = path;

		return NT_STATUS_OK;
	}

	return NT_STATUS_NOT_FOUND;
}

static NTSTATUS setup_driver_by_name(TALLOC_CTX *mem_ctx,
				     struct inf_context *inf_ctx,
				     const char *filename,
				     const char *environment,
				     const char *driver_name,
				     struct spoolss_AddDriverInfo8 *r,
				     const char **source_disk_name)
{
	NTSTATUS status;
	struct gp_inifile_context *ctx = inf_ctx->ctx;
	struct gp_inifile_context *core_ctx = inf_ctx->core_ctx;
	char *key;
	bool ok;
	const char *short_environment;
	const char *s;

	short_environment = spoolss_get_short_filesys_environment(environment);
	if (short_environment == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = find_driver_files(ctx, core_ctx, mem_ctx, driver_name, r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = process_source_disk_name(ctx, mem_ctx,
					  short_environment,
					  source_disk_name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	r->inf_path = talloc_strdup(mem_ctx, filename);
	if (r->inf_path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	r->architecture = talloc_strdup(mem_ctx, environment);
	if (r->architecture == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (r->print_processor == NULL) {
		r->print_processor = talloc_strdup(mem_ctx, "winprint");
		if (r->print_processor == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	status = gp_inifile_getstring_ext(ctx, "Version:Class", &s);
	if (NT_STATUS_IS_OK(status)) {
		if (strequal(s, "Printer")) {
			r->printer_driver_attributes |= PRINTER_DRIVER_CLASS;
		}
	}

	status = gp_inifile_getstring(ctx, "Version:Signature", &s);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!strequal(s, "\"$Windows NT$\"")) {
		return NT_STATUS_INVALID_SIGNATURE;
	}

	r->version = SPOOLSS_DRIVER_VERSION_200X;
	status = gp_inifile_getstring(ctx, "Version:ClassVer", &s);
	if (NT_STATUS_IS_OK(status)) {
		int cmp = strncasecmp_m(s, "4.0", 3);
		if (cmp == 0) {
			r->version = SPOOLSS_DRIVER_VERSION_2012;
		}
		if (strequal(s, "3.0")) {
			r->version = SPOOLSS_DRIVER_VERSION_200X;
		}
	}

	status = gp_inifile_getstring_ext(ctx, "Version:Provider", &s);
	if (NT_STATUS_IS_OK(status)) {
		if (s != NULL) {
			r->provider = talloc_strdup(mem_ctx, s);
			if (r->provider == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
		}
	}

	status = process_driver_driverver(ctx, r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	r->printer_driver_attributes &= ~PRINTER_DRIVER_SANDBOX_ENABLED;

	status = gp_inifile_getstring(ctx, "Version:DriverIsolation", &s);
	if (NT_STATUS_IS_OK(status)) {
		int cmp = strncasecmp_m(s, "2", 1);
		if (cmp == 0) {
			r->printer_driver_attributes |= PRINTER_DRIVER_SANDBOX_ENABLED;
		}
		cmp = strncasecmp_m(s, "0", 1);
		if (cmp == 0) {
			r->printer_driver_attributes &= ~PRINTER_DRIVER_SANDBOX_ENABLED;
		}
	}

	status = find_manufacturer_name(ctx, mem_ctx, "Manufacturer", &r->manufacturer_name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = find_manufacturer_url(ctx, mem_ctx, "OEM URLS", r->manufacturer_name, &r->manufacturer_url);
	if (!NT_STATUS_IS_OK(status)) {
		/* not critical */
	}

	status = gp_inifile_getbool(ctx, "PrinterPackageInstallation:PackageAware", &ok);
	if (NT_STATUS_IS_OK(status)) {
		if (ok) {
			r->printer_driver_attributes |= PRINTER_DRIVER_PACKAGE_AWARE;
		}
	}

	key = talloc_asprintf(mem_ctx, "%s.%s:%s",
		"PrinterPackageInstallation", short_environment, "PackageAware");
	if (key == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = gp_inifile_getbool(ctx, key, &ok);
	if (NT_STATUS_IS_OK(status)) {
		if (ok) {
			r->printer_driver_attributes |= PRINTER_DRIVER_PACKAGE_AWARE;
		}
	}

	key = talloc_asprintf(mem_ctx, "%s.%s:%s",
		"PrinterPackageInstallation", short_environment, "CoreDriverDependencies");
	if (key == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = gp_inifile_getstring(ctx, key, &s);
	if (NT_STATUS_IS_OK(status)) {
		char **list;
		r->core_driver_dependencies = talloc_zero(mem_ctx, struct spoolss_StringArray);
		if (r->core_driver_dependencies == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		list = str_list_make_v3(r->core_driver_dependencies, s, ",");
		if (list == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		r->core_driver_dependencies->string = const_str_list(list);
	}

	key = talloc_asprintf(mem_ctx, "%s.%s:%s",
		"PrinterPackageInstallation", short_environment, "InboxVersionRequired");
	if (key == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = gp_inifile_getstring(ctx, key, &s);
	if (NT_STATUS_IS_OK(status)) {
		if (strequal(s, "UseDriverVer")) {
			r->min_inbox_driver_ver_date = r->driver_date;
			r->min_inbox_driver_ver_version = r->driver_version;
		}
	}

	return NT_STATUS_OK;
}

/****************************************************************
 parse the a printer inf file
****************************************************************/

NTSTATUS driver_inf_parse(TALLOC_CTX *mem_ctx,
			  const char *core_driver_inf,
			  const char *filename,
			  const char *environment,
			  const char *driver_name,
			  struct spoolss_AddDriverInfo8 *r,
			  const char **source_disk_name)
{
	NTSTATUS status;
	struct inf_context *inf_ctx;

	if (!filename || !environment) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = init_inf_context(mem_ctx,
				  filename,
				  core_driver_inf,
				  &inf_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = setup_driver_by_name(mem_ctx, inf_ctx,
				      filename,
				      environment,
				      driver_name,
				      r,
				      source_disk_name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS driver_inf_list(TALLOC_CTX *mem_ctx,
			 const char *core_driver_inf,
			 const char *filename,
			 const char *environment,
			 uint32_t *count,
			 struct spoolss_AddDriverInfo8 **_r)
{
	NTSTATUS status;
	const char *short_environment;
	size_t num_devices = 0;
	const char **devices = NULL;
	const char **device_values = NULL;
	struct inf_context *inf_ctx;
	int d;

	if (!filename || !environment) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	short_environment = spoolss_get_short_filesys_environment(environment);
	if (short_environment == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = init_inf_context(mem_ctx,
				  filename,
				  core_driver_inf,
				  &inf_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = enum_devices_in_toc(inf_ctx->ctx, mem_ctx,
				     &num_devices,
				     &devices,
				     &device_values);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	for (d = 0; d < num_devices; d++) {

		struct spoolss_AddDriverInfo8 r;
		const char *source_disk_name;

		ZERO_STRUCT(r);

		status = setup_driver_by_name(mem_ctx, inf_ctx, filename,
					      environment, devices[d], &r,
					      &source_disk_name);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		ADD_TO_ARRAY(mem_ctx, struct spoolss_AddDriverInfo8, r, _r, count);
	}

	return NT_STATUS_OK;
}
