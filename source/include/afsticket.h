#ifndef _AFSTICKET_H_
#define _AFSTICKET_H_

#ifdef RENEWABLE_AFS_TICKET

struct Srvtabinfo{
  uid_t uid;
  pstring user;
};

#endif /* RENEWABLE_AFS_TICKET */

#endif /* _AFSTICKET_H_ */
