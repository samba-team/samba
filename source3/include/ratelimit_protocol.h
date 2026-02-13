/* Rate limiting protocol definitions for smbd ↔ ratelimitd communication */

#ifndef __RATELIMIT_PROTOCOL_H__
#define __RATELIMIT_PROTOCOL_H__

#include "lib/util/time.h"
#include "messages.h"

#define RATELIMITD_SOCKET_NAME "ratelimitd.sock"

/* Protocol version for compatibility checking */
#define RATELIMIT_PROTOCOL_VERSION 2
#define RATELIMIT_SHARE_NAME_LEN 256

static inline uint64_t time_now_usec(void)
{
	struct timespec ts;

	clock_gettime_mono(&ts);
	return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/* Operation types for rate limiting */
enum ratelimit_operation {
	RATELIMIT_OP_INVALID = 0,
	RATELIMIT_OP_READ = 1,
	RATELIMIT_OP_WRITE = 2,
};

/* Activity report from VFS process to local daemon via Unix socket */
struct ratelimit_activity_report {
	uint64_t timestamp_usec;
	int64_t recent_iops;
	uint32_t protocol_version;
	uint32_t operation;
	int32_t pid;
	uint32_t inflight_ios;
	char share_name[RATELIMIT_SHARE_NAME_LEN];
} PACKED_STRUCT;

/* Node summary broadcast from daemon to cluster */
struct ratelimit_node_summary {
	uint32_t vnn;
	int32_t process_count;
	uint64_t timestamp_usec;
	char share_name[RATELIMIT_SHARE_NAME_LEN];
} PACKED_STRUCT;

static inline uint32_t ratelimit_msg_type_summary(uint32_t operation)
{
	switch (operation) {
	case RATELIMIT_OP_READ:
		return MSG_VFS_AIO_RATELIMIT_READ_NODE_SUMMARY;
	case RATELIMIT_OP_WRITE:
		return MSG_VFS_AIO_RATELIMIT_WRITE_NODE_SUMMARY;
	default:
		return 0;
	}
}

static inline uint32_t ratelimit_op_from_string(const char *op_str)
{
	if (strcmp(op_str, "read") == 0) {
		return RATELIMIT_OP_READ;
	} else if (strcmp(op_str, "write") == 0) {
		return RATELIMIT_OP_WRITE;
	}
	return RATELIMIT_OP_INVALID;
}

static inline const char *ratelimit_op_to_string(uint32_t operation)
{
	switch (operation) {
	case RATELIMIT_OP_READ:
		return "read";
	case RATELIMIT_OP_WRITE:
		return "write";
	default:
		return "invalid";
	}
}

#endif /* __RATELIMIT_PROTOCOL_H__ */
