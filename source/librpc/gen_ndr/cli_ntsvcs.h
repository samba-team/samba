#include "librpc/gen_ndr/ndr_ntsvcs.h"
#ifndef __CLI_NTSVCS__
#define __CLI_NTSVCS__
NTSTATUS rpccli_PNP_Disconnect(struct rpc_pipe_client *cli,
			       TALLOC_CTX *mem_ctx,
			       WERROR *werror);
NTSTATUS rpccli_PNP_Connect(struct rpc_pipe_client *cli,
			    TALLOC_CTX *mem_ctx,
			    WERROR *werror);
NTSTATUS rpccli_PNP_GetVersion(struct rpc_pipe_client *cli,
			       TALLOC_CTX *mem_ctx,
			       uint16_t *version /* [out] [ref] */,
			       WERROR *werror);
NTSTATUS rpccli_PNP_GetGlobalState(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   WERROR *werror);
NTSTATUS rpccli_PNP_InitDetection(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  WERROR *werror);
NTSTATUS rpccli_PNP_ReportLogOn(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				WERROR *werror);
NTSTATUS rpccli_PNP_ValidateDeviceInstance(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   const char *devicepath /* [in] [ref,charset(UTF16)] */,
					   uint32_t flags /* [in]  */,
					   WERROR *werror);
NTSTATUS rpccli_PNP_GetRootDeviceInstance(struct rpc_pipe_client *cli,
					  TALLOC_CTX *mem_ctx,
					  WERROR *werror);
NTSTATUS rpccli_PNP_GetRelatedDeviceInstance(struct rpc_pipe_client *cli,
					     TALLOC_CTX *mem_ctx,
					     WERROR *werror);
NTSTATUS rpccli_PNP_EnumerateSubKeys(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     WERROR *werror);
NTSTATUS rpccli_PNP_GetDeviceList(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  WERROR *werror);
NTSTATUS rpccli_PNP_GetDeviceListSize(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx,
				      const char *devicename /* [in] [unique,charset(UTF16)] */,
				      uint32_t *size /* [out] [ref] */,
				      uint32_t flags /* [in]  */,
				      WERROR *werror);
NTSTATUS rpccli_PNP_GetDepth(struct rpc_pipe_client *cli,
			     TALLOC_CTX *mem_ctx,
			     WERROR *werror);
NTSTATUS rpccli_PNP_GetDeviceRegProp(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     const char *devicepath /* [in] [ref,charset(UTF16)] */,
				     uint32_t property /* [in]  */,
				     uint32_t *unknown1 /* [in,out] [ref] */,
				     uint8_t *buffer /* [out] [ref,length_is(*buffer_size),size_is(*buffer_size)] */,
				     uint32_t *buffer_size /* [in,out] [ref] */,
				     uint32_t *needed /* [in,out] [ref] */,
				     uint32_t unknown3 /* [in]  */,
				     WERROR *werror);
NTSTATUS rpccli_PNP_SetDeviceRegProp(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     WERROR *werror);
NTSTATUS rpccli_PNP_GetClassInstance(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     WERROR *werror);
NTSTATUS rpccli_PNP_CreateKey(struct rpc_pipe_client *cli,
			      TALLOC_CTX *mem_ctx,
			      WERROR *werror);
NTSTATUS rpccli_PNP_DeleteRegistryKey(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx,
				      WERROR *werror);
NTSTATUS rpccli_PNP_GetClassCount(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  WERROR *werror);
NTSTATUS rpccli_PNP_GetClassName(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 WERROR *werror);
NTSTATUS rpccli_PNP_DeleteClassKey(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   WERROR *werror);
NTSTATUS rpccli_PNP_GetInterfaceDeviceAlias(struct rpc_pipe_client *cli,
					    TALLOC_CTX *mem_ctx,
					    WERROR *werror);
NTSTATUS rpccli_PNP_GetInterfaceDeviceList(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   WERROR *werror);
NTSTATUS rpccli_PNP_GetInterfaceDeviceListSize(struct rpc_pipe_client *cli,
					       TALLOC_CTX *mem_ctx,
					       WERROR *werror);
NTSTATUS rpccli_PNP_RegisterDeviceClassAssociation(struct rpc_pipe_client *cli,
						   TALLOC_CTX *mem_ctx,
						   WERROR *werror);
NTSTATUS rpccli_PNP_UnregisterDeviceClassAssociation(struct rpc_pipe_client *cli,
						     TALLOC_CTX *mem_ctx,
						     WERROR *werror);
NTSTATUS rpccli_PNP_GetClassRegProp(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx,
				    WERROR *werror);
NTSTATUS rpccli_PNP_SetClassRegProp(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx,
				    WERROR *werror);
NTSTATUS rpccli_PNP_CreateDevInst(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  WERROR *werror);
NTSTATUS rpccli_PNP_DeviceInstanceAction(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 WERROR *werror);
NTSTATUS rpccli_PNP_GetDeviceStatus(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx,
				    WERROR *werror);
NTSTATUS rpccli_PNP_SetDeviceProblem(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     WERROR *werror);
NTSTATUS rpccli_PNP_DisableDevInst(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   WERROR *werror);
NTSTATUS rpccli_PNP_UninstallDevInst(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     WERROR *werror);
NTSTATUS rpccli_PNP_AddID(struct rpc_pipe_client *cli,
			  TALLOC_CTX *mem_ctx,
			  WERROR *werror);
NTSTATUS rpccli_PNP_RegisterDriver(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   WERROR *werror);
NTSTATUS rpccli_PNP_QueryRemove(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				WERROR *werror);
NTSTATUS rpccli_PNP_RequestDeviceEject(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       WERROR *werror);
NTSTATUS rpccli_PNP_IsDockStationPresent(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 WERROR *werror);
NTSTATUS rpccli_PNP_RequestEjectPC(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   WERROR *werror);
NTSTATUS rpccli_PNP_HwProfFlags(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				uint32_t unknown1 /* [in]  */,
				const char *devicepath /* [in] [ref,charset(UTF16)] */,
				uint32_t unknown2 /* [in]  */,
				uint32_t *unknown3 /* [in,out] [ref] */,
				uint16_t *unknown4 /* [in,out] [unique] */,
				const char *unknown5 /* [in] [unique,charset(UTF16)] */,
				const char **unknown5a /* [out] [unique,charset(UTF16)] */,
				uint32_t unknown6 /* [in]  */,
				uint32_t unknown7 /* [in]  */,
				WERROR *werror);
NTSTATUS rpccli_PNP_GetHwProfInfo(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  uint32_t idx /* [in]  */,
				  struct PNP_HwProfInfo *info /* [in,out] [ref] */,
				  uint32_t size /* [in]  */,
				  uint32_t flags /* [in]  */,
				  WERROR *werror);
NTSTATUS rpccli_PNP_AddEmptyLogConf(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx,
				    WERROR *werror);
NTSTATUS rpccli_PNP_FreeLogConf(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				WERROR *werror);
NTSTATUS rpccli_PNP_GetFirstLogConf(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx,
				    WERROR *werror);
NTSTATUS rpccli_PNP_GetNextLogConf(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   WERROR *werror);
NTSTATUS rpccli_PNP_GetLogConfPriority(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       WERROR *werror);
NTSTATUS rpccli_PNP_AddResDes(struct rpc_pipe_client *cli,
			      TALLOC_CTX *mem_ctx,
			      WERROR *werror);
NTSTATUS rpccli_PNP_FreeResDes(struct rpc_pipe_client *cli,
			       TALLOC_CTX *mem_ctx,
			       WERROR *werror);
NTSTATUS rpccli_PNP_GetNextResDes(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  WERROR *werror);
NTSTATUS rpccli_PNP_GetResDesData(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  WERROR *werror);
NTSTATUS rpccli_PNP_GetResDesDataSize(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx,
				      WERROR *werror);
NTSTATUS rpccli_PNP_ModifyResDes(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 WERROR *werror);
NTSTATUS rpccli_PNP_DetectResourceLimit(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx,
					WERROR *werror);
NTSTATUS rpccli_PNP_QueryResConfList(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     WERROR *werror);
NTSTATUS rpccli_PNP_SetHwProf(struct rpc_pipe_client *cli,
			      TALLOC_CTX *mem_ctx,
			      WERROR *werror);
NTSTATUS rpccli_PNP_QueryArbitratorFreeData(struct rpc_pipe_client *cli,
					    TALLOC_CTX *mem_ctx,
					    WERROR *werror);
NTSTATUS rpccli_PNP_QueryArbitratorFreeSize(struct rpc_pipe_client *cli,
					    TALLOC_CTX *mem_ctx,
					    WERROR *werror);
NTSTATUS rpccli_PNP_RunDetection(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 WERROR *werror);
NTSTATUS rpccli_PNP_RegisterNotification(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 WERROR *werror);
NTSTATUS rpccli_PNP_UnregisterNotification(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   WERROR *werror);
NTSTATUS rpccli_PNP_GetCustomDevProp(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     WERROR *werror);
NTSTATUS rpccli_PNP_GetVersionInternal(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       WERROR *werror);
NTSTATUS rpccli_PNP_GetBlockedDriverInfo(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 WERROR *werror);
NTSTATUS rpccli_PNP_GetServerSideDeviceInstallFlags(struct rpc_pipe_client *cli,
						    TALLOC_CTX *mem_ctx,
						    WERROR *werror);
#endif /* __CLI_NTSVCS__ */
