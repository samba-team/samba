/* * Samba Unix/Linux SMB client library
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

/**
 * @brief Functions to interact with an user.
 * @author Gregor Beck <gb@sernet.de>
 * @date   Aug 2011
 */

#ifndef __INTERACT_H
#define __INTERACT_H
#include <talloc.h>

char* interact_edit(TALLOC_CTX* mem_ctx, const char* str);
int interact_prompt(const char* msg, const char* accept, char def);



#endif /* __INTERACT_H */

/*Local Variables:*/
/*mode: c++*/
/*End:*/
