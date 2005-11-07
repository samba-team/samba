#include "perf.h"

void get_processinfo(PERF_DATA_BLOCK *data)
{
  int status;
  struct sysinfo info;
  status = sysinfo(&info);

  data->processInfo.data->runningProcessCount = (unsigned int)info.procs;

  return;
}

void init_processdata_desc(PERF_DATA_BLOCK *data)
{
  init_perf_counter(&(data->processInfo.processObjDesc),
		    &(data->processInfo.processObjDesc),
		    get_counter_id(data),
		    "Processes",
		    "%The Processes performance object displays aggregate information about processes on the machine.",
		    0,
		    PERF_OBJECT);
  init_perf_counter(&(data->processInfo.runningProcessCount),
		    &(data->processInfo.processObjDesc),
		    get_counter_id(data),
		    "Process Count",
		    "Process Count is the number of processes currently on the machine.",
		    PERF_SIZE_DWORD | PERF_TYPE_NUMBER | PERF_NUMBER_DECIMAL | PERF_DISPLAY_NO_SUFFIX,
		    PERF_COUNTER);
   
  return;
}

void init_process_data(PERF_DATA_BLOCK *data)
{
  data->processInfo.data = calloc(1, sizeof(*data->processInfo.data));
  if(!(data->processInfo.data))
    {
      perror("init_process_data: out of memory");
      exit(1);
    }
  
  init_processdata_desc(data);

  get_processinfo(data);

  return;
}

void output_processinfo(PERF_DATA_BLOCK *data, RuntimeSettings rt, int tdb_flags)
{
	output_perf_counter(data->processInfo.runningProcessCount,
			    (unsigned long long)data->processInfo.data->runningProcessCount,
			    rt, tdb_flags);

	return;
}

void output_process_desc(PERF_DATA_BLOCK *data, RuntimeSettings rt)
{
	output_perf_desc(data->processInfo.processObjDesc, rt);
	output_perf_desc(data->processInfo.runningProcessCount, rt);

	return;
}
