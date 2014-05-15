#ifndef IDTREE_H
#define IDTREE_H

struct idr_context *idr_init(TALLOC_CTX *mem_ctx);
int idr_get_new(struct idr_context *idp, void *ptr, int limit);
int idr_get_new_above(struct idr_context *idp, void *ptr, int starting_id, int limit);
int idr_get_new_random(struct idr_context *idp, void *ptr, int limit);
void *idr_find(struct idr_context *idp, int id);
int idr_remove(struct idr_context *idp, int id);

#endif /* IDTREE_H */
