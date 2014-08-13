/*
 * Trivial smb.conf parsing code
 * iniparser compatibility layer.
 *
 * Copyright Jeremy Allison <jra@samba.org> 2014
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License Version 3 or later, in which case the provisions
 * of the GPL are required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED `AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include "tini.h"
#include "tiniparser.h"

struct tiniparser_entry {
	struct tiniparser_entry *next_entry;
	char *key;
	char *value;
};

struct tiniparser_section {
	struct tiniparser_section *next_section;
	struct tiniparser_entry *entry_list;
	char section_name[];
};

struct tiniparser_dictionary {
	struct tiniparser_section *section_list;
};

/*
 * Find a section from a given key.
 * Also return start of subkey.
 * Return NULL if section name can't be found,
 * if no section name given, or no subkey given.
 */

static struct tiniparser_section *find_section(struct tiniparser_dictionary *d,
					const char *key,
					const char **subkey)
{
	struct tiniparser_section *curr_section;
	const char *p;
	size_t section_len;

	if (key == NULL) {
		return NULL;
	}
	p = strchr(key, ':');
	if (p == NULL) {
		/* No section. */
		return NULL;
	}

	section_len = p - key;
	/* Ensure we have at least one character of section name. */
	if (section_len == 0) {
		return NULL;
	}
	/* Ensure we have at least one character of subkey. */
	if (p[1] == '\0') {
		return NULL;
	}

	for (curr_section = d->section_list;
			curr_section;
			curr_section = curr_section->next_section) {
		/*
		 * Check if the key section matches the
		 * section name *exactly* (with terminating
		 * null after section_len characters.
		 */
		if ((strncasecmp(key, curr_section->section_name, section_len) == 0) &&
				(curr_section->section_name[section_len] == '\0')) {
			*subkey = p+1;
			return curr_section;
		}
	}
	return NULL;
}

static struct tiniparser_entry *find_entry(struct tiniparser_section *section,
					const char *key)
{
	struct tiniparser_entry *curr_entry;

	for (curr_entry = section->entry_list;
			curr_entry;
			curr_entry = curr_entry->next_entry) {
		if (strcasecmp(key,
				curr_entry->key) == 0) {
			return curr_entry;
		}
	}
	return NULL;
}

const char *tiniparser_getstring(struct tiniparser_dictionary *d,
			const char *key,
			const char *default_value)
{
	struct tiniparser_section *section;
	struct tiniparser_entry *entry;
	const char *subkey;

	section = find_section(d, key, &subkey);
	if (section == NULL) {
		return default_value;
	}

	entry = find_entry(section, subkey);
	if (entry == NULL) {
		return default_value;
	}

	return entry->value;
}


bool tiniparser_getboolean(struct tiniparser_dictionary *d,
			const char *key,
			bool default_value)
{
	const char *value = tiniparser_getstring(d, key, NULL);

	if (value == NULL) {
		return default_value;
	}

	switch(value[0]) {
		case '1':
		case 'T':
		case 't':
		case 'y':
		case 'Y':
			return true;
		case '0':
		case 'F':
		case 'f':
		case 'n':
		case 'N':
			return false;
		default:
			break;
	}

	return default_value;
}

int tiniparser_getint(struct tiniparser_dictionary *d,
			const char *key,
			int default_value)
{
	const char *value = tiniparser_getstring(d, key, NULL);

	if (value == NULL) {
		return default_value;
	}

	return (int)strtol(value, NULL, 0);
}

static bool value_parser(const char *key,
			const char *value,
			void *private_data)
{
	struct tiniparser_dictionary *d =
		(struct tiniparser_dictionary *)private_data;
	struct tiniparser_section *section = d->section_list;
	struct tiniparser_entry *entry = NULL;
	size_t val_len;
	size_t key_len;

	if (section == NULL) {
		return false;
	}
	if (key == NULL) {
		return false;
	}
	if (value == NULL) {
		return false;
	}

	key_len = strlen(key) + 1;
	val_len = strlen(value) + 1;

	entry = find_entry(section, key);
	if (entry) {
		/* Replace current value. */
		char *new_val = malloc(val_len);
		if (new_val == NULL) {
			return false;
		}
		memcpy(new_val, value, val_len);
		free(entry->value);
		entry->value = new_val;
		return true;
	}

	/* Create a new entry. */
	entry = malloc(sizeof(struct tiniparser_entry));
	if (entry == NULL) {
		return false;
	}
	entry->key = malloc(key_len);
	if (entry->key == NULL) {
		free(entry);
		return false;
	}
	memcpy(entry->key, key, key_len);

	entry->value = malloc(val_len);
	if (entry->value == NULL) {
		free(entry->key);
		free(entry);
		return false;
	}
	memcpy(entry->value, value, val_len);

	entry->next_entry = section->entry_list;
	section->entry_list = entry;
	return true;
}

static bool section_parser(const char *section_name,
			void *private_data)
{
	struct tiniparser_section **pp_section;
	struct tiniparser_section *new_section;
	struct tiniparser_dictionary *d =
		(struct tiniparser_dictionary *)private_data;
	size_t section_name_len;

	if (section_name == NULL) {
		return false;
	}

	/* Section names can't contain ':' */
	if (strchr(section_name, ':') != NULL) {
		return false;
	}

	/* Do we already have this section ? */
	for (pp_section = &d->section_list;
			*pp_section;
			pp_section = &(*pp_section)->next_section) {
		if (strcasecmp(section_name,
				(*pp_section)->section_name) == 0) {
			/*
			 * Move to the front of the list for
			 * value_parser() to find it.
			 */

			/* First save current entry. */
			struct tiniparser_section *curr_section = *pp_section;

			/* Now unlink current entry from list. */
			*pp_section = curr_section->next_section;

			/* Make current entry next point to whole list. */
			curr_section->next_section = d->section_list;

			/* And replace list with current entry at start. */
			d->section_list = curr_section;

			return true;
		}
	}

	section_name_len = strlen(section_name) + 1;

	/* Create new section. */
	new_section = malloc(
		offsetof(struct tiniparser_section, section_name) +
		section_name_len);
	if (new_section == NULL) {
		return false;
	}

	memcpy(new_section->section_name, section_name, section_name_len);

	new_section->entry_list = NULL;

	/* Add it to the head of the singly linked list. */
	new_section->next_section = d->section_list;
	d->section_list = new_section;
	return true;
}

struct tiniparser_dictionary *tiniparser_load(const char *filename)
{
	bool ret;
	struct tiniparser_dictionary *d = NULL;
	FILE *fp = fopen(filename, "r");

	if (fp == NULL) {
		return NULL;
	}

	d = malloc(sizeof(struct tiniparser_dictionary));
	if (d == NULL) {
		fclose(fp);
		return NULL;
	}
	d->section_list = NULL;

	ret = tini_parse(fp,
			section_parser,
			value_parser,
			d);
	fclose(fp);
	if (ret == false) {
		tiniparser_freedict(d);
		d = NULL;
	}
	return d;
}

void tiniparser_freedict(struct tiniparser_dictionary *d)
{
	struct tiniparser_section *curr_section, *next_section;

	if (d == NULL) {
		return;
	}

	for (curr_section = d->section_list;
			curr_section;
			curr_section = next_section) {
		struct tiniparser_entry *curr_entry, *next_entry;

		next_section = curr_section->next_section;

		for (curr_entry = curr_section->entry_list;
				curr_entry;
				curr_entry = next_entry) {
			next_entry = curr_entry->next_entry;

			free(curr_entry->key);
			free(curr_entry->value);
			free(curr_entry);
		}
		free(curr_section);
	}
	free(d);
}
