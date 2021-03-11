/*
 *  Maintain rap vs spoolss jobids
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


#ifndef __PRINTING_RAP_JOBID_H__
#define __PRINTING_RAP_JOBID_H__

#include "includes.h"

uint16_t pjobid_to_rap(const char *sharename, uint32_t jobid);
bool rap_to_pjobid(
	uint16_t rap_jobid, fstring sharename, uint32_t *pjobid);
void rap_jobid_delete(const char *sharename, uint32_t jobid);

#endif
