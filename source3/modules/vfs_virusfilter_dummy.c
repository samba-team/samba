/*
   Samba-VirusFilter VFS modules
   Dummy scanner with infected files support.
   Copyright (C) 2022 Pavel Filipenský <pfilipen@redhat.com>

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

#include "modules/vfs_virusfilter_utils.h"

static virusfilter_result virusfilter_dummy_scan(
	struct vfs_handle_struct *handle,
	struct virusfilter_config *config,
	const struct files_struct *fsp,
	char **reportp)
{
	bool ok;

	DBG_INFO("Scanning file: %s\n", fsp_str_dbg(fsp));
	ok = is_in_path(fsp->fsp_name->base_name,
			config->infected_files,
			false);
	return ok ? VIRUSFILTER_RESULT_INFECTED : VIRUSFILTER_RESULT_CLEAN;
}

static struct virusfilter_backend_fns virusfilter_backend_dummy = {
	.connect = NULL,
	.disconnect = NULL,
	.scan_init = NULL,
	.scan = virusfilter_dummy_scan,
	.scan_end = NULL,
};

int virusfilter_dummy_init(struct virusfilter_config *config)
{
	struct virusfilter_backend *backend = NULL;

	backend = talloc_zero(config, struct virusfilter_backend);
	if (backend == NULL) {
		return -1;
	}

	backend->fns = &virusfilter_backend_dummy;
	backend->name = "dummy";
	config->backend = backend;
	return 0;
}
