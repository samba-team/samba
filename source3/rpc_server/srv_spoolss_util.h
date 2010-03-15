/*
 *  Unix SMB/CIFS implementation.
 *
 *  SPOOLSS RPC Pipe server / winreg client routines
 *
 *  Copyright (c) 2010      Andreas Schneider <asn@samba.org>
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

#ifndef _SRV_SPOOLSS_UITL_H
#define _SRV_SPOOLSS_UITL_H

/**
 * @internal
 *
 * @brief Set printer data over the winreg pipe.
 *
 * @param[in]  p        The pipes structure to be able to open a new pipe.
 *
 * @param[in]  printer  The printer name.
 *
 * @param[in]  key      The key of the printer data to store the value.
 *
 * @param[in]  value    The value name to save.
 *
 * @param[in]  type     The type of the value to use.
 *
 * @param[in]  data     The data which sould be saved under the given value.
 *
 * @param[in]  data_size The size of the data.
 *
 * @return              On success WERR_OK, a corresponding DOS error is
 *                      something went wrong.
 */
WERROR winreg_set_printer_dataex(struct pipes_struct *p,
				 const char *printer,
				 const char *key,
				 const char *value,
				 enum winreg_Type type,
				 uint8_t *data,
				 uint32_t data_size);

#endif /* _SRV_SPOOLSS_UITL_H */
