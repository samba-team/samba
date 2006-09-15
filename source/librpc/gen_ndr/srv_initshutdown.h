#include "librpc/gen_ndr/ndr_initshutdown.h"
#ifndef __SRV_INITSHUTDOWN__
#define __SRV_INITSHUTDOWN__
WERROR _initshutdown_Init(pipes_struct *p, uint16_t *hostname, struct initshutdown_String *message, uint32_t timeout, uint8_t force_apps, uint8_t reboot);
WERROR _initshutdown_Abort(pipes_struct *p, uint16_t *server);
WERROR _initshutdown_InitEx(pipes_struct *p, uint16_t *hostname, struct initshutdown_String *message, uint32_t timeout, uint8_t force_apps, uint8_t reboot, uint32_t reason);
void initshutdown_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_initshutdown_init(void);
#endif /* __SRV_INITSHUTDOWN__ */
