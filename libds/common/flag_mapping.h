#ifndef __LIBDS_COMMON_FLAG_MAPPING_H__
#define __LIBDS_COMMON_FLAG_MAPPING_H__

/* The following definitions come from flag_mapping.c  */

uint32_t ds_acb2uf(uint32_t acb);
uint32_t ds_uf2acb(uint32_t uf);
uint32_t ds_uf2atype(uint32_t uf);
uint32_t ds_gtype2atype(uint32_t gtype);
enum lsa_SidType ds_atype_map(uint32_t atype);
uint32_t ds_uf2prim_group_rid(uint32_t uf);

#endif /* __LIBDS_COMMON_FLAG_MAPPING_H__ */
