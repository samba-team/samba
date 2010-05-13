/*
   Unix SMB/CIFS implementation.
   printcap headers

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

struct pcap_cache;

/* The following definitions come from printing/pcap.c  */

bool pcap_cache_add_specific(struct pcap_cache **ppcache, const char *name, const char *comment);
void pcap_cache_destroy_specific(struct pcap_cache **ppcache);
bool pcap_cache_add(const char *name, const char *comment);
bool pcap_cache_loaded(void);
void pcap_cache_replace(const struct pcap_cache *cache);
void pcap_printer_fn_specific(const struct pcap_cache *, void (*fn)(const char *, const char *, void *), void *);
void pcap_printer_fn(void (*fn)(const char *, const char *, void *), void *);

/* The following definitions come from printing/print_aix.c  */

bool aix_cache_reload(void);

/* The following definitions come from printing/print_cups.c  */

bool cups_cache_reload(void);
bool cups_pull_comment_location(TALLOC_CTX *mem_ctx,
				const char *printername,
				char **comment,
				char **location);

/* The following definitions come from printing/print_iprint.c  */

bool iprint_cache_reload(void);

/* The following definitions come from printing/print_svid.c  */

bool sysv_cache_reload(void);

/* The following definitions come from printing/print_standard.c  */
bool std_pcap_cache_reload(const char *pcap_name);
