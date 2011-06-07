
/* The following definitions come from passdb/machine_sid.c  */

struct dom_sid  *get_global_sam_sid(void);
void reset_global_sam_sid(void) ;
bool sid_check_is_domain(const struct dom_sid  *sid);
bool sid_check_is_in_our_domain(const struct dom_sid  *sid);
