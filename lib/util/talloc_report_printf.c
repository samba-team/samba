/*
 * talloc_report into a FILE
 *
 * Copyright Volker Lendecke <vl@samba.org> 2015
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

#include "replace.h"
#include "talloc_report_printf.h"

static void talloc_report_printf_helper(
	const void *ptr,
	int depth,
	int max_depth,
	int is_ref,
	void *private_data)
{
	FILE *f = private_data;
	const char *name = talloc_get_name(ptr);

	if (is_ref) {
		fprintf(f,
			"%*sreference to: %s\n",
			depth*4,
			"",
			name);
		return;
	}

	if (depth == 0) {
		fprintf(f,
			"%stalloc report on '%s' "
			"(total %6zu bytes in %3zu blocks)\n",
			(max_depth < 0 ? "full " :""), name,
			talloc_total_size(ptr),
			talloc_total_blocks(ptr));
		return;
	}

	if (strcmp(name, "char") == 0) {
		/*
		 * Print out the first 50 bytes of the string
		 */
		fprintf(f,
			"%*s%-30s contains %6zu bytes in %3zu blocks "
			"(ref %zu): %*s\n", depth*4, "", name,
			talloc_total_size(ptr),
			talloc_total_blocks(ptr),
			talloc_reference_count(ptr),
			(int)MIN(50, talloc_get_size(ptr)),
			(const char *)ptr);
		return;
	}

	fprintf(f,
		"%*s%-30s contains %6zu bytes in %3zu blocks (ref %zu) %p\n",
		depth*4, "", name,
		talloc_total_size(ptr),
		talloc_total_blocks(ptr),
		talloc_reference_count(ptr),
		ptr);
}

void talloc_full_report_printf(TALLOC_CTX *root, FILE *f)
{
	talloc_report_depth_cb(root, 0, -1, talloc_report_printf_helper, f);

#ifdef HAVE_MALLINFO
	{
		struct mallinfo mi;

		mi = mallinfo();
		fprintf(f,
			"mallinfo:\n"
			"    arena: %d\n"
			"    ordblks: %d\n"
			"    smblks: %d\n"
			"    hblks: %d\n"
			"    hblkhd: %d\n"
			"    usmblks: %d\n"
			"    fsmblks: %d\n"
			"    uordblks: %d\n"
			"    fordblks: %d\n"
			"    keepcost: %d\n",
			mi.arena,
			mi.ordblks,
			mi.smblks,
			mi.hblks,
			mi.hblkhd,
			mi.usmblks,
			mi.fsmblks,
			mi.uordblks,
			mi.fordblks,
			mi.keepcost);
	}
#endif /* HAVE_MALLINFO */
}
