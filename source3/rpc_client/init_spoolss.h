
/* The following definitions come from rpc_client/init_spoolss.c  */

bool init_systemtime(struct spoolss_Time *r,
		     struct tm *unixtime);
time_t spoolss_Time_to_time_t(const struct spoolss_Time *r);
WERROR pull_spoolss_PrinterData(TALLOC_CTX *mem_ctx,
				const DATA_BLOB *blob,
				union spoolss_PrinterData *data,
				enum winreg_Type type);
WERROR push_spoolss_PrinterData(TALLOC_CTX *mem_ctx, DATA_BLOB *blob,
				enum winreg_Type type,
				union spoolss_PrinterData *data);
void spoolss_printerinfo2_to_setprinterinfo2(const struct spoolss_PrinterInfo2 *i,
					     struct spoolss_SetPrinterInfo2 *s);

