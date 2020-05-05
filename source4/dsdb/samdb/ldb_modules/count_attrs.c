/*
   ldb database library

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2019

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

/*
 * Count how often different attributes are searched for, for performance
 * analysis. The counts are stored in tdb files in the 'debug' subdirectory of
 * Samba installation's private directory, and can be read using
 * script/attr_count_read.
 */

#include "includes.h"
#include "ldb_module.h"
#include "param/param.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "system/filesys.h"

#define NULL_ATTRS "__null_attrs__"
#define EMPTY_ATTRS "__empty_attrs__"
#define UNKNOWN_ATTR "__unknown_attribute__"
#define STAR_ATTR "*"

#define NULL_REQ_PSEUDO_N -2LL;
#define STAR_REQ_PSEUDO_N -4LL;

struct count_attrs_private {
	struct tdb_wrap *requested;
	struct tdb_wrap *duplicates;
	struct tdb_wrap *found;
	struct tdb_wrap *not_found;
	struct tdb_wrap *unwanted;
	struct tdb_wrap *star_match;
	struct tdb_wrap *null_req;
	struct tdb_wrap *empty_req;
	struct tdb_wrap *req_vs_found;
};


struct count_attrs_context {
	struct ldb_module *module;
	struct ldb_request *req;
	bool has_star;
	bool is_null;
	const char **requested_attrs;
	size_t n_attrs;
};


static int add_key(struct tdb_context *tdb,
		   struct TDB_DATA key)
{
	int ret;
	uint32_t one = 1;
	struct TDB_DATA value = {
		.dptr = (uint8_t *)&one,
		.dsize = sizeof(one)
	};
	ret = tdb_store(tdb,
			key,
			value,
			0);
	return ret;
}

static int increment_attr_count(struct tdb_context *tdb,
				const char *attr)
{
	/*
	 * Note that as we don't lock the database, there is a small window
	 * between the fetch and store in which identical updates from
	 * separate processes can race to clobber each other. If this happens
	 * the stored count will be one less than it should be.
	 *
	 * We don't worry about that because it should be quite rare and
	 * agnostic as to which counts are affected, meaning the overall
	 * statistical truth is preserved.
	 */
	int ret;
	uint32_t *val;
	TDB_DATA key = {
		.dptr = discard_const(attr),
		.dsize = strlen(attr)
	};

	TDB_DATA data = tdb_fetch(tdb, key);
	if (data.dptr == NULL) {
		ret = tdb_error(tdb);
		if (ret != TDB_ERR_NOEXIST) {
			const char *errstr = tdb_errorstr(tdb);
			DBG_ERR("tdb fetch error: %s\n", errstr);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		/* this key is unknown. We'll add it and get out of here. */
		ret = add_key(tdb, key);
		if (ret != 0) {
			DBG_ERR("could not add %s: %d\n", attr, ret);
		}
		return ret;
	}

	val = (uint32_t *)data.dptr;
	(*val)++;

	ret = tdb_store(tdb,
			key,
			data,
			0);

	if (ret != 0) {
		const char *errstr = tdb_errorstr(tdb);
		DBG_ERR("tdb store error: %s\n", errstr);
		free(data.dptr);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	free(data.dptr);
	return LDB_SUCCESS;
}


static int increment_req_vs_found(struct tdb_context *tdb,
				  struct count_attrs_context *ac,
				  size_t n_found)
{
	/*
	 * Here we record the number of elements in each reply along with the
	 * number of attributes in the corresponding request. Requests for
	 * NULL and "*" are arbitrarily given the attribute counts -2 and -4
	 * respectively. This leads them to be plotted as two stacks on the
	 * left hand side of the scatter plot.
	 */
	int ret;
	ssize_t k[2];
	uint32_t *val = NULL;
	TDB_DATA key = {
		.dptr = (unsigned char *)k,
		.dsize = sizeof(k)
	};
	TDB_DATA data = {0};
	ssize_t n_req = ac->n_attrs;
	if (ac->is_null) {
		n_req = NULL_REQ_PSEUDO_N;
	} else if (ac->has_star) {
		n_req = STAR_REQ_PSEUDO_N;
	}
	k[0] = n_req;
	k[1] = n_found;

	data = tdb_fetch(tdb, key);
	if (data.dptr == NULL) {
		ret = tdb_error(tdb);
		if (ret != TDB_ERR_NOEXIST) {
			const char *errstr = tdb_errorstr(tdb);
			DBG_ERR("req vs found fetch error: %s\n", errstr);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		/* unknown key */
		ret = add_key(tdb, key);
		if (ret != 0) {
			DBG_ERR("could not add req vs found %zu:%zu: %d\n",
				n_req, n_found, ret);
		}
		return ret;
	}

	val = (uint32_t *)data.dptr;
	(*val)++;

	ret = tdb_store(tdb, key, data, 0);
	if (ret != 0) {
		const char *errstr = tdb_errorstr(tdb);
		DBG_ERR("req vs found store error: %s\n", errstr);
		free(data.dptr);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	free(data.dptr);
	return LDB_SUCCESS;
}


static int strcasecmp_ptr(const char **a, const char **b)
{
	return strcasecmp(*a, *b);
}


static const char **get_sorted_attrs(TALLOC_CTX *mem_ctx,
				     const char * const *unsorted_attrs,
				     size_t n_attrs)
{
	size_t i;
	const char **attrs = talloc_array(mem_ctx,
					  const char *,
					  n_attrs);

	if (attrs == NULL) {
		return NULL;
	}
	for (i = 0; i < n_attrs; i++) {
		const char *a = unsorted_attrs[i];
		if (a == NULL) {
			DBG_ERR("attrs have disappeared! "
				"wanted %zu; got %zu\n",
				n_attrs, i);
			talloc_free(attrs);
			return NULL;
		}
		attrs[i] = a;
	}

	qsort(attrs, n_attrs, sizeof(char *), QSORT_CAST strcasecmp_ptr);
	return attrs;
}



static int count_attrs_search_callback(struct ldb_request *req,
				       struct ldb_reply *ares)
{
	struct count_attrs_private *priv = NULL;
	struct ldb_message *msg = NULL;
	size_t i, j;
	int ret;

	struct count_attrs_context *ac = \
		talloc_get_type(req->context,
				struct count_attrs_context);

	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);

	priv = talloc_get_type_abort(ldb_module_get_private(ac->module),
				     struct count_attrs_private);

	if (ares == NULL) {
		DBG_ERR("ares is NULL\n");
		return ldb_module_done(ac->req, NULL, NULL,
				       LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		DBG_INFO("ares error %d\n", ares->error);
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_REFERRAL:
		return ldb_module_send_referral(ac->req, ares->referral);

	case LDB_REPLY_DONE:
		return ldb_module_done(ac->req, ares->controls,
				       ares->response, LDB_SUCCESS);

	case LDB_REPLY_ENTRY:
		msg = ares->message;
		if (ac->is_null || ac->n_attrs == 0) {
			struct tdb_context *tdb = NULL;
			/*
			 * Note when attributes are found when the requested
			 * list was empty or NULL
			 */
			if (ac->is_null) {
				tdb = priv->null_req->tdb;
			} else {
				tdb = priv->empty_req->tdb;
			}
			for (i = 0; i < msg->num_elements; i++) {
				const char *name = msg->elements[i].name;
				ret = increment_attr_count(tdb, name);
				if (ret != LDB_SUCCESS) {
					talloc_free(ares);
					DBG_ERR("inc failed\n");
					return ret;
				}
			}
		} else {
			/*
			 * We make sorted lists of the requested and found
			 * elements, which makes it easy to find missing or
			 * intruding values.
			 */
			struct tdb_context *found_tdb = priv->found->tdb;
			struct tdb_context *unwanted_tdb = \
				priv->unwanted->tdb;
			struct tdb_context *star_match_tdb = \
				priv->star_match->tdb;
			struct tdb_context *not_found_tdb = \
				priv->not_found->tdb;

			const char **requested_attrs = ac->requested_attrs;
			const char **found_attrs = \
				talloc_array(ac, const char *,
					     msg->num_elements);
			if (found_attrs == NULL) {
				return ldb_oom(ldb);
			}

			for (i = 0; i < msg->num_elements; i++) {
				found_attrs[i] = msg->elements[i].name;
			}

			qsort(found_attrs, msg->num_elements, sizeof(char *),
			      QSORT_CAST strcasecmp_ptr);


			/* find and report duplicates */
			for (i = 1; i < msg->num_elements; i++) {
				if (strcasecmp(found_attrs[i],
					       found_attrs[i - 1]) == 0) {
					DBG_ERR("duplicate element: %s!\n",
						found_attrs[i]);
					/*
					 * If this happens it will muck up our
					 * counts, but probably have worse
					 * effects on the rest of the module
					 * stack. */
				}
			}

			/*
			 * This next bit is like the merge stage of a
			 * mergesort, but instead of merging we only detect
			 * absense or presence.
			 */
			i = 0;
			j = 0;
			while (i < ac->n_attrs ||
			       j < msg->num_elements) {
				int cmp;
				if (i >= ac->n_attrs) {
					cmp = 1;
				} else if (j >= msg->num_elements) {
					cmp = -1;
				} else {
					cmp = strcasecmp(requested_attrs[i],
							 found_attrs[j]
						);
				}

				if (cmp < 0) {
					/* We did not find the element */
					ret = increment_attr_count(
						not_found_tdb,
						requested_attrs[i]);
					i++;
				} else if (cmp > 0) {
					/*
					 * We found the element, but didn't
					 * specifically ask for it.
					 */
					if (ac->has_star) {
						ret = increment_attr_count(
							star_match_tdb,
							found_attrs[j]);
					} else {
						ret = increment_attr_count(
							unwanted_tdb,
							found_attrs[j]);
					}
					j++;
				} else {
					/* We got what we asked for. */
					ret = increment_attr_count(
						found_tdb,
						found_attrs[j]);
					i++;
					j++;
				}
				if (ret != LDB_SUCCESS) {
					talloc_free(ares);
					DBG_ERR("inc failed\n");
					return ret;
				}
			}
		}
		ret = increment_req_vs_found(priv->req_vs_found->tdb,
					     ac,
					     msg->num_elements);

		if (ret != LDB_SUCCESS) {
			talloc_free(ares);
			DBG_ERR("inc of req vs found failed\n");
			return ret;
		}

		return ldb_module_send_entry(
			ac->req,
			ares->message,
			ares->controls);
	}

	talloc_free(ares);
	return LDB_SUCCESS;
}


static int count_attrs_search(struct ldb_module *module,
			      struct ldb_request *req)
{
	int ret;
	const char * const *attrs = req->op.search.attrs;
	struct count_attrs_private *count_attrs_private = NULL;
	struct tdb_context *tdb = NULL;
	struct ldb_request *down_req = NULL;
	struct count_attrs_context *ac = NULL;
	bool has_star = false;
	bool is_null = false;
	size_t n_attrs = 0;
	const char **sorted_attrs = NULL;
	struct ldb_context *ldb = ldb_module_get_ctx(module);


	void *untyped_private = ldb_module_get_private(module);
	if (untyped_private == NULL) {
		/*
		 * There are some cases (in early start up, and during a
		 * backup restore) in which we get a NULL private object, in
		 * which case all we can do is ignore it and pass the request
		 * on unexamined.
		 */
		return ldb_next_request(module, req);
	}

	count_attrs_private = talloc_get_type_abort(untyped_private,
						    struct count_attrs_private);
	tdb = count_attrs_private->requested->tdb;

	ac = talloc_zero(req, struct count_attrs_context);
	if (ac == NULL) {
		return ldb_oom(ldb);
	}

	if (attrs == NULL) {
		ret = increment_attr_count(tdb, NULL_ATTRS);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return ret;
		}
		is_null = true;
	} else if (attrs[0] == NULL) {
		ret = increment_attr_count(tdb, EMPTY_ATTRS);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return ret;
		}
	} else {
		size_t i, j;
		for (i = 0; attrs[i] != NULL; i++) {
			ret = increment_attr_count(tdb, attrs[i]);
			if (ret != LDB_SUCCESS) {
				talloc_free(ac);
				return ret;
			}
			if (strcmp("*", attrs[i]) == 0) {
				has_star = true;
			}
		}
		n_attrs = i;
		sorted_attrs = get_sorted_attrs(req,
						attrs,
						n_attrs);
		/*
		 * Find, report, and remove duplicates. Duplicate attrs in
		 * requests are allowed, but don't work well with our
		 * merge-count algorithm.
		 */
		j = 0;
		for (i = 1; i < n_attrs; i++) {
			if (strcasecmp(sorted_attrs[i],
				       sorted_attrs[j]) == 0) {
				ret = increment_attr_count(
					count_attrs_private->duplicates->tdb,
					sorted_attrs[i]);
				if (ret != LDB_SUCCESS) {
					talloc_free(ac);
					return ret;
				}
			} else {
				j++;
				if (j != i) {
					sorted_attrs[j] = sorted_attrs[i];
				}
			}
		}
		n_attrs = j;
	}

	ac->module = module;
	ac->req = req;
	ac->has_star = has_star;
	ac->is_null = is_null;
	ac->n_attrs = n_attrs;
	ac->requested_attrs = sorted_attrs;

	ret = ldb_build_search_req_ex(&down_req,
				      ldb,
				      ac,
				      req->op.search.base,
				      req->op.search.scope,
				      req->op.search.tree,
				      req->op.search.attrs,
				      req->controls,
				      ac,
				      count_attrs_search_callback,
				      req);
	if (ret != LDB_SUCCESS) {
		return ldb_operr(ldb);
	}

	return ldb_next_request(module, down_req);
}


static struct tdb_wrap * open_private_tdb(TALLOC_CTX *mem_ctx,
					  struct loadparm_context *lp_ctx,
					  const char *name)
{
	struct tdb_wrap *store = NULL;
	char *filename = lpcfg_private_path(mem_ctx, lp_ctx, name);

	if (filename == NULL) {
		return NULL;
	}

	store = tdb_wrap_open(mem_ctx, filename, 1000,
			      TDB_CLEAR_IF_FIRST,
			      O_RDWR | O_CREAT,
			      0660);
	if (store == NULL) {
		DBG_ERR("failed to open tdb at %s\n", filename);
	}
	TALLOC_FREE(filename);
	return store;
}

static int make_private_dir(TALLOC_CTX *mem_ctx,
			    struct loadparm_context *lp_ctx,
			    const char *name)
{
	int ret;
	char *dirname = lpcfg_private_path(mem_ctx, lp_ctx, name);
	if (dirname == NULL) {
		return -1;
	}
	ret = mkdir(dirname, 0755);
	TALLOC_FREE(dirname);
	return ret;
}


static int count_attrs_init(struct ldb_module *module)
{
	struct ldb_context *ldb = NULL;
	struct count_attrs_private *data = NULL;
	struct loadparm_context *lp_ctx = NULL;
	int ret;

	ldb = ldb_module_get_ctx(module);

	data = talloc_zero(module, struct count_attrs_private);
	if (data == NULL) {
		return ldb_oom(ldb);
	}

	lp_ctx = talloc_get_type(ldb_get_opaque(ldb, "loadparm"),
				 struct loadparm_context);

	ret = make_private_dir(data, lp_ctx, "debug");
	if (ret != 0) {
		goto no_private_dir;
	}
	data->requested = open_private_tdb(data, lp_ctx,
					   "debug/attr_counts_requested.tdb");
	data->duplicates =			\
		open_private_tdb(data, lp_ctx,
				 "debug/attr_counts_duplicates.tdb");
	data->found = open_private_tdb(data, lp_ctx,
				       "debug/attr_counts_found.tdb");
	data->not_found = open_private_tdb(data, lp_ctx,
					   "debug/attr_counts_not_found.tdb");
	data->unwanted = open_private_tdb(data, lp_ctx,
					  "debug/attr_counts_unwanted.tdb");
	data->star_match = open_private_tdb(data, lp_ctx,
					    "debug/attr_counts_star_match.tdb");
	data->null_req = open_private_tdb(data, lp_ctx,
					  "debug/attr_counts_null_req.tdb");
	data->empty_req = open_private_tdb(data, lp_ctx,
					   "debug/attr_counts_empty_req.tdb");
	data->req_vs_found =			\
		open_private_tdb(data, lp_ctx,
				 "debug/attr_counts_req_vs_found.tdb");
	if (data->requested == NULL ||
	    data->duplicates == NULL ||
	    data->found == NULL ||
	    data->not_found == NULL ||
	    data->unwanted == NULL ||
	    data->star_match == NULL ||
	    data->null_req == NULL ||
	    data->empty_req == NULL ||
	    data->req_vs_found == NULL) {
		goto no_private_dir;
	}

	ldb_module_set_private(module, data);
	return ldb_next_init(module);

  no_private_dir:
	/*
	 * If we leave the private data NULL, the search function knows not to
	 * do anything.
	 */
	DBG_WARNING("the count_attrs module could not open its databases\n");
	DBG_WARNING("attributes will not be counted.\n");
	TALLOC_FREE(data);
	ldb_module_set_private(module, NULL);
	return ldb_next_init(module);
}

static const struct ldb_module_ops ldb_count_attrs_module_ops = {
	.name		   = "count_attrs",
	.search		   = count_attrs_search,
	.init_context	   = count_attrs_init
};

int ldb_count_attrs_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_count_attrs_module_ops);
}
