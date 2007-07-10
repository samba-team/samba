/* 
 *  Unix SMB/CIFS implementation.
 *  Copyright (C) Jelmer Vernooij			2005
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

#include "includes.h"
#include "lib/util/dlinklist.h"
#include "param/param.h"
#include "system/filesys.h"

struct param_section *param_get_section(struct param_context *ctx, const char *name)
{
	struct param_section *sect;

	if (name == NULL) 
		name = GLOBAL_NAME;

	for (sect = ctx->sections; sect; sect = sect->next) {
		if (!strcasecmp_m(sect->name, name)) 
			return sect;
	}

	return NULL;
}

struct param *param_section_get (struct param_section *section, const char *name)
{
	struct param *p;

	for (p = section->parameters; p; p = p->next) {
		if (strcasecmp_m(p->name, name) == 0) 
			return p;
	}

	return NULL;
}

struct param *param_get (struct param_context *ctx, const char *section_name, const char *name)
{
	struct param_section *section = param_get_section(ctx, section_name);
	if (section == NULL)
		return NULL;

	return param_section_get(section, name);
}

/* Look up parameter. If it is not found, add it */
static struct param *param_get_add(struct param_context *ctx, const char *section_name, const char *name)
{
	struct param_section *section;
	struct param *p;

	section = param_get_section(ctx, section_name);

	if (section == NULL) {
		section = talloc_zero(ctx, struct param_section);
		if (section == NULL)
			return NULL;

		section->name = talloc_strdup(section, section_name);
		DLIST_ADD(ctx->sections, section);
	}

	p = param_section_get(section, name);
	if (p == NULL) {
		p = talloc_zero(section, struct param);
		if (p == NULL)
			return NULL;

		p->name = talloc_strdup(p, name);
		DLIST_ADD(section->parameters, p);
	}
	
	return p;
}

const char *param_get_string(struct param_context *ctx, const char *section, const char *param)
{
	struct param *p = param_get(ctx, section, param);

	if (p == NULL)
		return NULL;

	return p->value;
}

int param_set_string(struct param_context *ctx, const char *section, const char *param, const char *value)
{
	struct param *p = param_get_add(ctx, section, param);

	if (p == NULL)
		return -1;

	p->value = talloc_strdup(p, value);

	return 0;
}

const char **param_get_string_list(struct param_context *ctx, const char *section, const char *param,
				 const char *separator)
{
	struct param *p = param_get(ctx, section, param);
	
	if (p == NULL)
		return NULL;

	if (separator == NULL)
		separator = LIST_SEP;
	
	if (p->list_value == NULL) {
		p->list_value = str_list_make(ctx, p->value, separator);
	}

	return p->list_value;
}

int param_set_string_list(struct param_context *ctx, const char *section, const char *param, const char **list)
{
	struct param *p = param_get_add(ctx, section, param);	

	p->value = str_list_join(p, list, ' ');
	p->list_value = str_list_copy(p, list);

	return 0;
}

int param_get_int(struct param_context *ctx, const char *section, const char *param, int default_v)
{
	const char *value = param_get_string(ctx, section, param);
	
	if (value)
		return strtol(value, NULL, 0); 

	return default_v;
}

void param_set_int(struct param_context *ctx, const char *section, const char *param, int value)
{
	struct param *p = param_get_add(ctx, section, param);

	if (!p) 
		return;

	p->value = talloc_asprintf(p, "%d", value);
}

unsigned long param_get_ulong(struct param_context *ctx, const char *section, const char *param, unsigned long default_v)
{
	const char *value = param_get_string(ctx, section, param);
	
	if (value)
		return strtoul(value, NULL, 0);

	return default_v;
}

void param_set_ulong(struct param_context *ctx, const char *section, const char *name, unsigned long value)
{
	struct param *p = param_get_add(ctx, section, name);

	if (!p)
		return;

	p->value = talloc_asprintf(p, "%lu", value);
}

static BOOL param_sfunc (const char *name, void *_ctx)
{
	struct param_context *ctx = _ctx;
	struct param_section *section = param_get_section(ctx, name);

	if (section == NULL) {
		section = talloc_zero(ctx, struct param_section);
		if (section == NULL)
			return False;

		section->name = talloc_strdup(section, name);

		DLIST_ADD(ctx->sections, section);
	}

	/* Make sure this section is on top of the list for param_pfunc */
	DLIST_PROMOTE(ctx->sections, section);

	return True;
}

static BOOL param_pfunc (const char *name, const char *value, void *_ctx)
{
	struct param_context *ctx = _ctx;
	struct param *p = param_section_get(ctx->sections, name);

	if (!p) {
		p = talloc_zero(ctx->sections, struct param);
		if (p == NULL)
			return False;

		p->name = talloc_strdup(p, name);
		p->value = talloc_strdup(p, value);
		DLIST_ADD(ctx->sections->parameters, p);
	} else { /* Replace current value */
		talloc_free(p->value);
		p->value = talloc_strdup(p, value);
	}

	return True;
}

struct param_context *param_init(TALLOC_CTX *mem_ctx)
{
	return talloc_zero(mem_ctx, struct param_context);
}


int param_read(struct param_context *ctx, const char *fn)
{
	ctx->sections = talloc_zero(ctx, struct param_section);
	if (ctx->sections == NULL)
		return -1;

	ctx->sections->name = talloc_strdup(ctx->sections, "global");
	if (!pm_process( fn, param_sfunc, param_pfunc, ctx)) {
		return -1;
	}

	return 0;
}

int param_write(struct param_context *ctx, const char *fn)
{
	int file;
	struct param_section *section;

	if (fn == NULL || ctx == NULL)
		return -1;

	file = open(fn, O_WRONLY|O_CREAT, 0755);

	if (file == -1)
		return -1;
	
	for (section = ctx->sections; section; section = section->next) {
		struct param *param;
		
		fdprintf(file, "[%s]\n", section->name);
		for (param = section->parameters; param; param = param->next) {
			fdprintf(file, "\t%s = %s\n", param->name, param->value);
		}
		fdprintf(file, "\n");
	}

	close(file);

	return 0;
}
