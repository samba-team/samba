/*
 * talloc_report into a FILE
 *
 * Copyright Volker Lendecke <vl@samba.org> 2019
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _TALLOC_REPORT_PRINTF_H_
#define _TALLOC_REPORT_PRINTF_H_

#include "replace.h"
#include "system/filesys.h"
#include <talloc.h>

void talloc_full_report_printf(TALLOC_CTX *root, FILE *f);

#endif
