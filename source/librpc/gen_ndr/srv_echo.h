#include "librpc/gen_ndr/ndr_echo.h"
#ifndef __SRV_RPCECHO__
#define __SRV_RPCECHO__
void _echo_AddOne(pipes_struct *p, uint32_t in_data, uint32_t *out_data);
void _echo_EchoData(pipes_struct *p, uint32_t len, uint8_t *in_data, uint8_t *out_data);
void _echo_SinkData(pipes_struct *p, uint32_t len, uint8_t *data);
void _echo_SourceData(pipes_struct *p, uint32_t len, uint8_t *data);
void _echo_TestCall(pipes_struct *p, const char *s1, const char **s2);
NTSTATUS _echo_TestCall2(pipes_struct *p, uint16_t level, union echo_Info *info);
uint32 _echo_TestSleep(pipes_struct *p, uint32_t seconds);
void _echo_TestEnum(pipes_struct *p, enum echo_Enum1 *foo1, struct echo_Enum2 *foo2, union echo_Enum3 *foo3);
void _echo_TestSurrounding(pipes_struct *p, struct echo_Surrounding *data);
uint16 _echo_TestDoublePointer(pipes_struct *p, uint16_t ***data);
void rpcecho_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_rpcecho_init(void);
#endif /* __SRV_RPCECHO__ */
