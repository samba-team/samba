#include "perf.h"

void get_meminfo(PERF_DATA_BLOCK *data)
{
    int status;
    struct sysinfo info;
    status = sysinfo(&info);
    
    data->memInfo.data->availPhysKb = (info.freeram * info.mem_unit)/1024;
    data->memInfo.data->availSwapKb = (info.freeswap * info.mem_unit)/1024;
    data->memInfo.data->totalPhysKb = (info.totalram * info.mem_unit)/1024;
    data->memInfo.data->totalSwapKb = (info.totalswap * info.mem_unit)/1024;

    /* Also get uptime since we have the structure */
    data->PerfTime = (unsigned long)info.uptime;

    return;
}

void init_memdata_desc(PERF_DATA_BLOCK *data)
{
    init_perf_counter(&(data->memInfo.memObjDesc),
		      &(data->memInfo.memObjDesc),
		      get_counter_id(data),
		      "Memory",
		      "The Memory performance object consists of counters that describe the behavior of physical and virtual memory on the computer.",
		      0,
		      PERF_OBJECT);
    init_perf_counter(&(data->memInfo.availPhysKb),
		      &(data->memInfo.memObjDesc),
		      get_counter_id(data),
		      "Available Physical Kilobytes",
		      "Available Physical Kilobytes is the number of free kilobytes in physical memory",
		      PERF_SIZE_DWORD | PERF_TYPE_NUMBER | PERF_NUMBER_DECIMAL | PERF_DISPLAY_NO_SUFFIX,
		      PERF_COUNTER);
    init_perf_counter(&(data->memInfo.availSwapKb),
		      &(data->memInfo.memObjDesc),
		      get_counter_id(data),
		      "Available Swap Kilobytes",
		      "Available Swap Kilobytes is the number of free kilobytes in swap space",
		      PERF_SIZE_DWORD | PERF_TYPE_NUMBER | PERF_NUMBER_DECIMAL | PERF_DISPLAY_NO_SUFFIX,
		      PERF_COUNTER);
    init_perf_counter(&(data->memInfo.totalPhysKb),
		      &(data->memInfo.memObjDesc),
		      get_counter_id(data),
		      "Total Physical Kilobytes",
		      "Total Physical Kilobytes is a base counter",
		      PERF_SIZE_DWORD | PERF_TYPE_NUMBER | PERF_NUMBER_DECIMAL | PERF_COUNTER_BASE | PERF_DISPLAY_NOSHOW,
		      PERF_COUNTER);
    init_perf_counter(&(data->memInfo.totalSwapKb),
		      &(data->memInfo.memObjDesc),
		      get_counter_id(data),
		      "Total Swap Kilobytes",
		      "Total Swap Kilobytes is a base counter",
		      PERF_SIZE_DWORD | PERF_TYPE_NUMBER | PERF_NUMBER_DECIMAL | PERF_COUNTER_BASE | PERF_DISPLAY_NOSHOW,
		      PERF_COUNTER);

    return;
}

void init_mem_data(PERF_DATA_BLOCK *data)
{
    data->memInfo.data = calloc(1, sizeof(*data->memInfo.data));
    if(!data->memInfo.data)
    {
	perror("init_memdata: out of memory");
	exit(1);
    }

    init_memdata_desc(data);

    get_meminfo(data);

    return;
}

void output_mem_desc(PERF_DATA_BLOCK *data, RuntimeSettings rt)
{
    output_perf_desc(data->memInfo.memObjDesc, rt);
    output_perf_desc(data->memInfo.availPhysKb, rt);
    output_perf_desc(data->memInfo.availSwapKb, rt);
    output_perf_desc(data->memInfo.totalPhysKb, rt);
    output_perf_desc(data->memInfo.totalSwapKb, rt);

    return;
}

void output_meminfo(PERF_DATA_BLOCK *data, RuntimeSettings rt, int tdb_flags)
{
    output_perf_counter(data->memInfo.availPhysKb, 
			(unsigned long long)data->memInfo.data->availPhysKb, 
			rt, tdb_flags);
    output_perf_counter(data->memInfo.availSwapKb, 
			(unsigned long long)data->memInfo.data->availSwapKb,
			rt, tdb_flags);
    output_perf_counter(data->memInfo.totalPhysKb,
			(unsigned long long)data->memInfo.data->totalPhysKb,
			rt, tdb_flags);
    output_perf_counter(data->memInfo.totalSwapKb,
			(unsigned long long)data->memInfo.data->totalSwapKb,
			rt, tdb_flags);

    return;
}
