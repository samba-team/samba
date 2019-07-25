/*
   Configuration file handling on top of tini

   Copyright (C) Amitay Isaacs  2017

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/locale.h"

#include <talloc.h>

#include "lib/util/dlinklist.h"
#include "lib/util/tini.h"
#include "lib/util/debug.h"

#include "common/conf.h"

struct conf_value {
	enum conf_type type;
	union {
		const char *string;
		int integer;
		bool boolean;
	} data;
};

union conf_pointer {
	const char **string;
	int *integer;
	bool *boolean;
};

struct conf_option {
	struct conf_option *prev, *next;

	const char *name;
	enum conf_type type;
	void *validate;

	struct conf_value default_value;
	bool default_set;

	struct conf_value *value, *new_value;
	union conf_pointer ptr;
	bool temporary_modified;
};

struct conf_section {
	struct conf_section *prev, *next;

	const char *name;
	conf_validate_section_fn validate;
	struct conf_option *option;
};

struct conf_context {
	const char *filename;
	struct conf_section *section;
	bool define_failed;
	bool ignore_unknown;
	bool reload;
	bool validation_active;
};

/*
 * Functions related to conf_value
 */

static int string_to_string(TALLOC_CTX *mem_ctx,
			    const char *str,
			    const char **str_val)
{
	char *t;

	if (str == NULL) {
		return EINVAL;
	}

	t = talloc_strdup(mem_ctx, str);
	if (t == NULL) {
		return ENOMEM;
	}

	*str_val = t;
	return 0;
}

static int string_to_integer(const char *str, int *int_val)
{
	long t;
	char *endptr = NULL;

	if (str == NULL) {
		return EINVAL;
	}

	t = strtol(str, &endptr, 0);
	if (*str != '\0' || endptr == NULL) {
		if (t < 0 || t > INT_MAX) {
			return EINVAL;
		}

		*int_val = (int)t;
		return 0;
	}

	return EINVAL;
}

static int string_to_boolean(const char *str, bool *bool_val)
{
	if (strcasecmp(str, "true") == 0 || strcasecmp(str, "yes") == 0) {
		*bool_val = true;
		return 0;
	}

	if (strcasecmp(str, "false") == 0 || strcasecmp(str, "no") == 0) {
		*bool_val = false;
		return 0;
	}

	return EINVAL;
}

static int conf_value_from_string(TALLOC_CTX *mem_ctx,
				  const char *str,
				  struct conf_value *value)
{
	int ret;

	switch (value->type) {
	case CONF_STRING:
		ret = string_to_string(mem_ctx, str, &value->data.string);
		break;

	case CONF_INTEGER:
		ret = string_to_integer(str, &value->data.integer);
		break;

	case CONF_BOOLEAN:
		ret = string_to_boolean(str, &value->data.boolean);
		break;

	default:
		return EINVAL;
	}

	return ret;
}

static bool conf_value_compare(struct conf_value *old, struct conf_value *new)
{
	if (old == NULL || new == NULL) {
		return false;
	}

	if (old->type != new->type) {
		return false;
	}

	switch (old->type) {
	case CONF_STRING:
		if (old->data.string == NULL && new->data.string == NULL) {
			return true;
		}
		if (old->data.string != NULL && new->data.string != NULL) {
			if (strcmp(old->data.string, new->data.string) == 0) {
				return true;
			}
		}
		break;

	case CONF_INTEGER:
		if (old->data.integer == new->data.integer) {
			return true;
		}
		break;

	case CONF_BOOLEAN:
		if (old->data.boolean == new->data.boolean) {
			return true;
		}
		break;
	}

	return false;
}

static int conf_value_copy(TALLOC_CTX *mem_ctx,
			   struct conf_value *src,
			   struct conf_value *dst)
{
	if (src->type != dst->type) {
		return EINVAL;
	}

	switch (src->type) {
	case CONF_STRING:
		if (dst->data.string != NULL) {
			talloc_free(discard_const(dst->data.string));
		}
		if (src->data.string == NULL) {
			dst->data.string = NULL;
		} else {
			dst->data.string = talloc_strdup(
				mem_ctx, src->data.string);
			if (dst->data.string == NULL) {
				return ENOMEM;
			}
		}
		break;

	case CONF_INTEGER:
		dst->data.integer = src->data.integer;
		break;

	case CONF_BOOLEAN:
		dst->data.boolean = src->data.boolean;
		break;

	default:
		return EINVAL;
	}

	return 0;
}

static void conf_value_dump(const char *key,
			    struct conf_value *value,
			    bool is_default,
			    bool is_temporary,
			    FILE *fp)
{
	if ((value->type == CONF_STRING && value->data.string == NULL) ||
	    is_default) {
		fprintf(fp, "\t# %s = ", key);
	} else {
		fprintf(fp, "\t%s = ", key);
	}

	switch (value->type) {
	case CONF_STRING:
		if (value->data.string != NULL) {
			fprintf(fp, "%s", value->data.string);
		}
		break;

	case CONF_INTEGER:
		fprintf(fp, "%d", value->data.integer);
		break;

	case CONF_BOOLEAN:
		fprintf(fp, "%s", (value->data.boolean ? "true" : "false"));
		break;
	}

	if (is_temporary) {
		fprintf(fp, " # temporary");
	}

	fprintf(fp, "\n");
}

/*
 * Functions related to conf_option
 */

static struct conf_option *conf_option_find(struct conf_section *s,
					    const char *key)
{
	struct conf_option *opt;

	for (opt = s->option; opt != NULL; opt = opt->next) {
		if (strcmp(opt->name, key) == 0) {
			return opt;
		}
	}

	return NULL;
}

static void conf_option_set_ptr_value(struct conf_option *opt)
{
	switch (opt->type) {
	case CONF_STRING:
		if (opt->ptr.string != NULL) {
			*(opt->ptr.string) = opt->value->data.string;
		}
		break;

	case CONF_INTEGER:
		if (opt->ptr.integer != NULL) {
			*(opt->ptr.integer) = opt->value->data.integer;
		}
		break;

	case CONF_BOOLEAN:
		if (opt->ptr.boolean != NULL) {
			*(opt->ptr.boolean) = opt->value->data.boolean;
		}
		break;
	}
}

static void conf_option_default(struct conf_option *opt);

static int conf_option_add(struct conf_section *s,
			   const char *key,
			   enum conf_type type,
			   void *validate,
			   struct conf_option **popt)
{
	struct conf_option *opt;

	opt = conf_option_find(s, key);
	if (opt != NULL) {
		D_ERR("conf: option \"%s\" already exists\n", key);
		return EEXIST;
	}

	opt = talloc_zero(s, struct conf_option);
	if (opt == NULL) {
		return ENOMEM;
	}

	opt->name = talloc_strdup(opt, key);
	if (opt->name == NULL) {
		talloc_free(opt);
		return ENOMEM;
	}

	opt->type = type;
	opt->validate = validate;

	DLIST_ADD_END(s->option, opt);

	if (popt != NULL) {
		*popt = opt;
	}

	return 0;
}

static int conf_option_set_default(struct conf_option *opt,
				   struct conf_value *default_value)
{
	int ret;

	opt->default_value.type = opt->type;

	ret = conf_value_copy(opt, default_value, &opt->default_value);
	if (ret != 0) {
		return ret;
	}

	opt->default_set = true;
	opt->temporary_modified = false;

	return 0;
}

static void conf_option_set_ptr(struct conf_option *opt,
				union conf_pointer *ptr)
{
	opt->ptr = *ptr;
}

static bool conf_option_validate_string(struct conf_option *opt,
					struct conf_value *value,
					enum conf_update_mode mode)
{
	conf_validate_string_option_fn validate =
		(conf_validate_string_option_fn)opt->validate;

	return validate(opt->name,
			opt->value->data.string,
			value->data.string,
			mode);
}

static bool conf_option_validate_integer(struct conf_option *opt,
					 struct conf_value *value,
					 enum conf_update_mode mode)
{
	conf_validate_integer_option_fn validate =
		(conf_validate_integer_option_fn)opt->validate;

	return validate(opt->name,
			opt->value->data.integer,
			value->data.integer,
			mode);
}

static bool conf_option_validate_boolean(struct conf_option *opt,
					 struct conf_value *value,
					 enum conf_update_mode mode)
{
	conf_validate_boolean_option_fn validate =
		(conf_validate_boolean_option_fn)opt->validate;

	return validate(opt->name,
			opt->value->data.boolean,
			value->data.boolean,
			mode);
}

static bool conf_option_validate(struct conf_option *opt,
				 struct conf_value *value,
				 enum conf_update_mode mode)
{
	int ret;

	if (opt->validate == NULL) {
		return true;
	}

	switch (opt->type) {
	case CONF_STRING:
		ret = conf_option_validate_string(opt, value, mode);
		break;

	case CONF_INTEGER:
		ret = conf_option_validate_integer(opt, value, mode);
		break;

	case CONF_BOOLEAN:
		ret = conf_option_validate_boolean(opt, value, mode);
		break;

	default:
		ret = EINVAL;
	}

	return ret;
}

static bool conf_option_same_value(struct conf_option *opt,
				   struct conf_value *new_value)
{
	return conf_value_compare(opt->value, new_value);
}

static int conf_option_new_value(struct conf_option *opt,
				 struct conf_value *new_value,
				 enum conf_update_mode mode)
{
	int ret;
	bool ok;

	if (opt->new_value != &opt->default_value) {
		TALLOC_FREE(opt->new_value);
	}

	if (new_value == &opt->default_value) {
		/*
		 * This happens only during load/reload. Set the value to
		 * default value, so if the config option is dropped from
		 * config file, then it get's reset to default.
		 */
		opt->new_value = &opt->default_value;
	} else {
		ok = conf_option_validate(opt, new_value, mode);
		if (!ok) {
			D_ERR("conf: validation for option \"%s\" failed\n",
			      opt->name);
			return EINVAL;
		}

		opt->new_value = talloc_zero(opt, struct conf_value);
		if (opt->new_value == NULL) {
			return ENOMEM;
		}

		opt->new_value->type = opt->value->type;
		ret = conf_value_copy(opt, new_value, opt->new_value);
		if (ret != 0) {
			return ret;
		}
	}

	conf_option_set_ptr_value(opt);

	if (new_value != &opt->default_value) {
		if (mode == CONF_MODE_API) {
			opt->temporary_modified = true;
		} else {
			opt->temporary_modified = false;
		}
	}

	return 0;
}

static int conf_option_new_default_value(struct conf_option *opt,
					 enum conf_update_mode mode)
{
	return conf_option_new_value(opt, &opt->default_value, mode);
}

static void conf_option_default(struct conf_option *opt)
{
	if (! opt->default_set) {
		return;
	}

	if (opt->value != &opt->default_value) {
		TALLOC_FREE(opt->value);
	}

	opt->value = &opt->default_value;
	conf_option_set_ptr_value(opt);
}

static void conf_option_reset(struct conf_option *opt)
{
	if (opt->new_value != &opt->default_value) {
		TALLOC_FREE(opt->new_value);
	}

	conf_option_set_ptr_value(opt);
}

static void conf_option_update(struct conf_option *opt)
{
	if (opt->new_value == NULL) {
		return;
	}

	if (opt->value != &opt->default_value) {
		TALLOC_FREE(opt->value);
	}

	opt->value = opt->new_value;
	opt->new_value = NULL;

	conf_option_set_ptr_value(opt);
}

static void conf_option_reset_temporary(struct conf_option *opt)
{
	opt->temporary_modified = false;
}

static bool conf_option_is_default(struct conf_option *opt)
{
	return (opt->value == &opt->default_value);
}

static void conf_option_dump(struct conf_option *opt, FILE *fp)
{
	bool is_default;

	is_default = conf_option_is_default(opt);

	conf_value_dump(opt->name,
			opt->value,
			is_default,
			opt->temporary_modified,
			fp);
}

/*
 * Functions related to conf_section
 */

static struct conf_section *conf_section_find(struct conf_context *conf,
					      const char *section)
{
	struct conf_section *s;

	for (s = conf->section; s != NULL; s = s->next) {
		if (strcasecmp(s->name, section) == 0) {
			return s;
		}
	}

	return NULL;
}

static int conf_section_add(struct conf_context *conf,
			    const char *section,
			    conf_validate_section_fn validate)
{
	struct conf_section *s;

	s = conf_section_find(conf, section);
	if (s != NULL) {
		return EEXIST;
	}

	s = talloc_zero(conf, struct conf_section);
	if (s == NULL) {
		return ENOMEM;
	}

	s->name = talloc_strdup(s, section);
	if (s->name == NULL) {
		talloc_free(s);
		return ENOMEM;
	}

	s->validate = validate;

	DLIST_ADD_END(conf->section, s);
	return 0;
}

static bool conf_section_validate(struct conf_context *conf,
				  struct conf_section *s,
				  enum conf_update_mode mode)
{
	bool ok;

	if (s->validate == NULL) {
		return true;
	}

	ok = s->validate(conf, s->name, mode);
	if (!ok) {
		D_ERR("conf: validation for section [%s] failed\n", s->name);
	}

	return ok;
}

static void conf_section_dump(struct conf_section *s, FILE *fp)
{
	fprintf(fp, "[%s]\n", s->name);
}

/*
 * Functions related to conf_context
 */

static void conf_all_default(struct conf_context *conf)
{
	struct conf_section *s;
	struct conf_option *opt;

	for (s = conf->section; s != NULL; s = s->next) {
		for (opt = s->option; opt != NULL; opt = opt->next) {
			conf_option_default(opt);
		}
	}
}

static int conf_all_temporary_default(struct conf_context *conf,
				      enum conf_update_mode mode)
{
	struct conf_section *s;
	struct conf_option *opt;
	int ret;

	for (s = conf->section; s != NULL; s = s->next) {
		for (opt = s->option; opt != NULL; opt = opt->next) {
			ret = conf_option_new_default_value(opt, mode);
			if (ret != 0) {
				return ret;
			}
		}
	}

	return 0;
}

static void conf_all_reset(struct conf_context *conf)
{
	struct conf_section *s;
	struct conf_option *opt;

	for (s = conf->section; s != NULL; s = s->next) {
		for (opt = s->option; opt != NULL; opt = opt->next) {
			conf_option_reset(opt);
		}
	}
}

static void conf_all_update(struct conf_context *conf)
{
	struct conf_section *s;
	struct conf_option *opt;

	for (s = conf->section; s != NULL; s = s->next) {
		for (opt = s->option; opt != NULL; opt = opt->next) {
			conf_option_update(opt);
			conf_option_reset_temporary(opt);
		}
	}
}

/*
 * API functions
 */

int conf_init(TALLOC_CTX *mem_ctx, struct conf_context **result)
{
	struct conf_context *conf;

	conf = talloc_zero(mem_ctx, struct conf_context);
	if (conf == NULL) {
		return ENOMEM;
	}

	conf->define_failed = false;

	*result = conf;
	return 0;
}

void conf_define_section(struct conf_context *conf,
			 const char *section,
			 conf_validate_section_fn validate)
{
	int ret;

	if (conf->define_failed) {
		return;
	}

	if (section == NULL) {
		conf->define_failed = true;
		return;
	}

	ret = conf_section_add(conf, section, validate);
	if (ret != 0) {
		conf->define_failed = true;
		return;
	}
}

static struct conf_option *conf_define(struct conf_context *conf,
				       const char *section,
				       const char *key,
				       enum conf_type type,
				       conf_validate_string_option_fn validate)
{
	struct conf_section *s;
	struct conf_option *opt;
	int ret;

	s = conf_section_find(conf, section);
	if (s == NULL) {
		D_ERR("conf: unknown section [%s]\n", section);
		return NULL;
	}

	if (key == NULL) {
		D_ERR("conf: option name null in section [%s]\n", section);
		return NULL;
	}

	ret = conf_option_add(s, key, type, validate, &opt);
	if (ret != 0) {
		return NULL;
	}

	return opt;
}

static void conf_define_post(struct conf_context *conf,
			     struct conf_option *opt,
			     struct conf_value *default_value)
{
	int ret;

	ret = conf_option_set_default(opt, default_value);
	if (ret != 0) {
		conf->define_failed = true;
		return;
	}

	conf_option_default(opt);
}

void conf_define_string(struct conf_context *conf,
			const char *section,
			const char *key,
			const char *default_str_val,
			conf_validate_string_option_fn validate)
{
	struct conf_option *opt;
	struct conf_value default_value;

	if (! conf_valid(conf)) {
		return;
	}

	opt = conf_define(conf, section, key, CONF_STRING, validate);
	if (opt == NULL) {
		conf->define_failed = true;
		return;
	}

	default_value.type = CONF_STRING;
	default_value.data.string = default_str_val;

	conf_define_post(conf, opt, &default_value);
}

void conf_define_integer(struct conf_context *conf,
			 const char *section,
			 const char *key,
			 const int default_int_val,
			 conf_validate_integer_option_fn validate)
{
	struct conf_option *opt;
	struct conf_value default_value;

	if (! conf_valid(conf)) {
		return;
	}

	opt = conf_define(conf, section, key, CONF_INTEGER, (void *)validate);
	if (opt == NULL) {
		conf->define_failed = true;
		return;
	}

	default_value.type = CONF_INTEGER;
	default_value.data.integer = default_int_val;

	conf_define_post(conf, opt, &default_value);
}


void conf_define_boolean(struct conf_context *conf,
			 const char *section,
			 const char *key,
			 const bool default_bool_val,
			 conf_validate_boolean_option_fn validate)
{
	struct conf_option *opt;
	struct conf_value default_value;

	if (! conf_valid(conf)) {
		return;
	}

	opt = conf_define(conf, section, key, CONF_BOOLEAN, (void *)validate);
	if (opt == NULL) {
		conf->define_failed = true;
		return;
	}

	default_value.type = CONF_BOOLEAN;
	default_value.data.boolean = default_bool_val;

	conf_define_post(conf, opt, &default_value);
}

static struct conf_option *_conf_option(struct conf_context *conf,
					const char *section,
					const char *key)
{
	struct conf_section *s;
	struct conf_option *opt;

	s = conf_section_find(conf, section);
	if (s == NULL) {
		return NULL;
	}

	opt = conf_option_find(s, key);
	return opt;
}

void conf_assign_string_pointer(struct conf_context *conf,
				const char *section,
				const char *key,
				const char **str_ptr)
{
	struct conf_option *opt;
	union conf_pointer ptr;

	opt = _conf_option(conf, section, key);
	if (opt == NULL) {
		D_ERR("conf: unknown option [%s] -> \"%s\"\n", section, key);
		conf->define_failed = true;
		return;
	}

	if (opt->type != CONF_STRING) {
		conf->define_failed = true;
		return;
	}

	ptr.string = str_ptr;
	conf_option_set_ptr(opt, &ptr);
	conf_option_set_ptr_value(opt);
}

void conf_assign_integer_pointer(struct conf_context *conf,
				 const char *section,
				 const char *key,
				 int *int_ptr)
{
	struct conf_option *opt;
	union conf_pointer ptr;

	opt = _conf_option(conf, section, key);
	if (opt == NULL) {
		D_ERR("conf: unknown option [%s] -> \"%s\"\n", section, key);
		conf->define_failed = true;
		return;
	}

	if (opt->type != CONF_INTEGER) {
		conf->define_failed = true;
		return;
	}

	ptr.integer = int_ptr;
	conf_option_set_ptr(opt, &ptr);
	conf_option_set_ptr_value(opt);
}

void conf_assign_boolean_pointer(struct conf_context *conf,
				 const char *section,
				 const char *key,
				 bool *bool_ptr)
{
	struct conf_option *opt;
	union conf_pointer ptr;

	opt = _conf_option(conf, section, key);
	if (opt == NULL) {
		D_ERR("conf: unknown option [%s] -> \"%s\"\n", section, key);
		conf->define_failed = true;
		return;
	}

	if (opt->type != CONF_BOOLEAN) {
		conf->define_failed = true;
		return;
	}

	ptr.boolean = bool_ptr;
	conf_option_set_ptr(opt, &ptr);
	conf_option_set_ptr_value(opt);
}

bool conf_query(struct conf_context *conf,
		const char *section,
		const char *key,
		enum conf_type *type)
{
	struct conf_section *s;
	struct conf_option *opt;

	if (! conf_valid(conf)) {
		return false;
	}

	s = conf_section_find(conf, section);
	if (s == NULL) {
		return false;
	}

	opt = conf_option_find(s, key);
	if (opt == NULL) {
		return false;
	}

	if (type != NULL) {
		*type = opt->type;
	}
	return true;
}

bool conf_valid(struct conf_context *conf)
{
	if (conf->define_failed) {
		return false;
	}

	return true;
}

void conf_set_defaults(struct conf_context *conf)
{
	conf_all_default(conf);
}

struct conf_load_state {
	struct conf_context *conf;
	struct conf_section *s;
	enum conf_update_mode mode;
	int err;
};

static bool conf_load_section(const char *section, void *private_data);
static bool conf_load_option(const char *name,
			     const char *value_str,
			     void *private_data);

static int conf_load_internal(struct conf_context *conf)
{
	struct conf_load_state state;
	FILE *fp;
	int ret;
	bool ok;

	state = (struct conf_load_state) {
		.conf = conf,
		.mode = (conf->reload ? CONF_MODE_RELOAD : CONF_MODE_LOAD),
	};

	ret = conf_all_temporary_default(conf, state.mode);
	if (ret != 0) {
		return ret;
	}

	fp = fopen(conf->filename, "r");
	if (fp == NULL) {
		return errno;
	}

	ok = tini_parse(fp,
			false,
			conf_load_section,
			conf_load_option,
			&state);
	fclose(fp);
	if (!ok) {
		goto fail;
	}

	/* Process the last section */
	if (state.s != NULL) {
		ok = conf_section_validate(conf, state.s, state.mode);
		if (!ok) {
			state.err = EINVAL;
			goto fail;
		}
	}

	if (state.err != 0) {
		goto fail;
	}

	conf_all_update(conf);
	return 0;

fail:
	conf_all_reset(conf);
	return state.err;
}

static bool conf_load_section(const char *section, void *private_data)
{
	struct conf_load_state *state =
		(struct conf_load_state *)private_data;
	bool ok;

	if (state->s != NULL) {
		ok = conf_section_validate(state->conf, state->s, state->mode);
		if (!ok) {
			state->err = EINVAL;
			return true;
		}
	}

	state->s = conf_section_find(state->conf, section);
	if (state->s == NULL) {
		if (state->conf->ignore_unknown) {
			D_DEBUG("conf: ignoring unknown section [%s]\n",
				section);
		} else {
			D_ERR("conf: unknown section [%s]\n", section);
			state->err = EINVAL;
			return true;
		}
	}

	return true;
}

static bool conf_load_option(const char *name,
			     const char *value_str,
			     void *private_data)
{
	struct conf_load_state *state =
		(struct conf_load_state *)private_data;
	struct conf_option *opt;
	TALLOC_CTX *tmp_ctx;
	struct conf_value value;
	int ret;
	bool ok;

	if (state->s == NULL) {
		if (state->conf->ignore_unknown) {
			D_DEBUG("conf: unknown section for option \"%s\"\n",
				name);
			return true;
		} else {
			D_ERR("conf: unknown section for option \"%s\"\n",
			      name);
			state->err = EINVAL;
			return true;
		}
	}

	opt = conf_option_find(state->s, name);
	if (opt == NULL) {
		if (state->conf->ignore_unknown) {
			D_DEBUG("conf: unknown option [%s] -> \"%s\"\n",
				state->s->name,
				name);
			return true;
		} else {
			D_ERR("conf: unknown option [%s] -> \"%s\"\n",
			      state->s->name,
			      name);
			state->err = EINVAL;
			return true;
		}
	}

	if (strlen(value_str) == 0) {
		D_ERR("conf: empty value [%s] -> \"%s\"\n",
		      state->s->name,
		      name);
		state->err = EINVAL;
		return true;
	}

	tmp_ctx = talloc_new(state->conf);
	if (tmp_ctx == NULL) {
		state->err = ENOMEM;
		return false;
	}

	value.type = opt->type;
	ret = conf_value_from_string(tmp_ctx, value_str, &value);
	if (ret != 0) {
		D_ERR("conf: invalid value [%s] -> \"%s\" = \"%s\"\n",
		      state->s->name,
		      name,
		      value_str);
		talloc_free(tmp_ctx);
		state->err = ret;
		return true;
	}

	ok = conf_option_same_value(opt, &value);
	if (ok) {
		goto done;
	}

	ret = conf_option_new_value(opt, &value, state->mode);
	if (ret != 0) {
		talloc_free(tmp_ctx);
		state->err = ret;
		return true;
	}

done:
	talloc_free(tmp_ctx);
	return true;

}

int conf_load(struct conf_context *conf,
	      const char *filename,
	      bool ignore_unknown)
{
	conf->filename = talloc_strdup(conf, filename);
	if (conf->filename == NULL) {
		return ENOMEM;
	}

	conf->ignore_unknown = ignore_unknown;

	D_NOTICE("Reading config file %s\n", filename);

	return conf_load_internal(conf);
}

int conf_reload(struct conf_context *conf)
{
	int ret;

	if (conf->filename == NULL) {
		return EPERM;
	}

	D_NOTICE("Re-reading config file %s\n", conf->filename);

	conf->reload = true;
	ret = conf_load_internal(conf);
	conf->reload = false;

	return ret;
}

static int conf_set(struct conf_context *conf,
		    const char *section,
		    const char *key,
		    struct conf_value *value)
{
	struct conf_section *s;
	struct conf_option *opt;
	int ret;
	bool ok;

	s = conf_section_find(conf, section);
	if (s == NULL) {
		return EINVAL;
	}

	opt = conf_option_find(s, key);
	if (opt == NULL) {
		return EINVAL;
	}

	if (opt->type != value->type) {
		return EINVAL;
	}

	ok = conf_option_same_value(opt, value);
	if (ok) {
		return 0;
	}

	ret = conf_option_new_value(opt, value, CONF_MODE_API);
	if (ret != 0) {
		conf_option_reset(opt);
		return ret;
	}

	ok = conf_section_validate(conf, s, CONF_MODE_API);
	if (!ok) {
		conf_option_reset(opt);
		return EINVAL;
	}

	conf_option_update(opt);
	return 0;
}

int conf_set_string(struct conf_context *conf,
		    const char *section,
		    const char *key,
		    const char *str_val)
{
	struct conf_value value;

	value.type = CONF_STRING;
	value.data.string = str_val;

	return conf_set(conf, section, key, &value);
}

int conf_set_integer(struct conf_context *conf,
		     const char *section,
		     const char *key,
		     int int_val)
{
	struct conf_value value;

	value.type = CONF_INTEGER;
	value.data.integer = int_val;

	return conf_set(conf, section, key, &value);
}

int conf_set_boolean(struct conf_context *conf,
		     const char *section,
		     const char *key,
		     bool bool_val)
{
	struct conf_value value;

	value.type = CONF_BOOLEAN;
	value.data.boolean = bool_val;

	return conf_set(conf, section, key, &value);
}

static int conf_get(struct conf_context *conf,
		    const char *section,
		    const char *key,
		    enum conf_type type,
		    const struct conf_value **value,
		    bool *is_default)
{
	struct conf_section *s;
	struct conf_option *opt;

	s = conf_section_find(conf, section);
	if (s == NULL) {
		return EINVAL;
	}

	opt = conf_option_find(s, key);
	if (opt == NULL) {
		return EINVAL;
	}

	if (opt->type != type) {
		return EINVAL;
	}

	*value = opt->value;
	if (is_default != NULL) {
		*is_default = conf_option_is_default(opt);
	}

	return 0;
}

int conf_get_string(struct conf_context *conf,
		    const char *section,
		    const char *key,
		    const char **str_val,
		    bool *is_default)
{
	const struct conf_value *value;
	int ret;

	ret = conf_get(conf, section, key, CONF_STRING, &value, is_default);
	if (ret != 0) {
		return ret;
	}

	*str_val = value->data.string;
	return 0;
}

int conf_get_integer(struct conf_context *conf,
		     const char *section,
		     const char *key,
		     int *int_val,
		     bool *is_default)
{
	const struct conf_value *value;
	int ret;

	ret = conf_get(conf, section, key, CONF_INTEGER, &value, is_default);
	if (ret != 0) {
		return ret;
	}

	*int_val = value->data.integer;
	return 0;
}

int conf_get_boolean(struct conf_context *conf,
		     const char *section,
		     const char *key,
		     bool *bool_val,
		     bool *is_default)
{
	const struct conf_value *value;
	int ret;

	ret = conf_get(conf, section, key, CONF_BOOLEAN, &value, is_default);
	if (ret != 0) {
		return ret;
	}

	*bool_val = value->data.boolean;
	return 0;
}

void conf_dump(struct conf_context *conf, FILE *fp)
{
	struct conf_section *s;
	struct conf_option *opt;

	for (s = conf->section; s != NULL; s = s->next) {
		conf_section_dump(s, fp);
		for (opt = s->option; opt != NULL; opt = opt->next) {
			conf_option_dump(opt, fp);
		}
	}
}
