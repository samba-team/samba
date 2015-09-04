/*
 * File Server Remote VSS Protocol (FSRVP) server
 *
 * Copyright (C) David Disseldorp	2012-2015
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

#ifndef _SRV_FSS_AGENT_H_
#define _SRV_FSS_AGENT_H_

NTSTATUS srv_fssa_start(struct messaging_context *msg_ctx);
void srv_fssa_cleanup(void);

#endif /*_SRV_FSS_AGENT_H_ */
