/* 
 * $Id$ 
 */

#ifndef __KDC_H__
#define __KDC_H__

struct db_entry{
    krb5_principal principal;
    krb5_keyblock keyblock;
    int kvno;
    time_t max_life;
    time_t max_renew;
};


#endif /* __KDC_H__ */
