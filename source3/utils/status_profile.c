/*
 * Unix SMB/CIFS implementation.
 * status reporting
 * Copyright (C) Andrew Tridgell 1994-1998
 * Copyright (C) James Peach 2005-2006
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbprofile.h"
#include "status_profile.h"

static void profile_separator(const char * title)
{
    char line[79 + 1];
    char * end;

    snprintf(line, sizeof(line), "**** %s ", title);

    for (end = line + strlen(line); end < &line[sizeof(line) -1]; ++end) {
	    *end = '*';
    }

    line[sizeof(line) - 1] = '\0';
    d_printf("%s\n", line);
}

/*******************************************************************
 dump the elements of the profile structure
  ******************************************************************/
bool status_profile_dump(bool verbose)
{
	struct profile_stats stats = {};

	if (!profile_setup(NULL, True)) {
		fprintf(stderr,"Failed to initialise profile memory\n");
		return False;
	}

	smbprofile_collect(&stats);

#define __PRINT_FIELD_LINE(name, _stats, field) do { \
	d_printf("%-59s%20ju\n", \
		 name "_" #field ":", \
		 (uintmax_t)stats.values._stats.field); \
} while(0);
#define SMBPROFILE_STATS_START
#define SMBPROFILE_STATS_SECTION_START(name, display) profile_separator(#display);
#define SMBPROFILE_STATS_COUNT(name) do { \
	__PRINT_FIELD_LINE(#name, name##_stats,  count); \
} while(0);
#define SMBPROFILE_STATS_TIME(name) do { \
	__PRINT_FIELD_LINE(#name, name##_stats,  time); \
} while(0);
#define SMBPROFILE_STATS_BASIC(name) do { \
	__PRINT_FIELD_LINE(#name, name##_stats,  count); \
	__PRINT_FIELD_LINE(#name, name##_stats,  time); \
} while(0);
#define SMBPROFILE_STATS_BYTES(name) do { \
	__PRINT_FIELD_LINE(#name, name##_stats,  count); \
	__PRINT_FIELD_LINE(#name, name##_stats,  time); \
	__PRINT_FIELD_LINE(#name, name##_stats,  idle); \
	__PRINT_FIELD_LINE(#name, name##_stats,  bytes); \
} while(0);
#define SMBPROFILE_STATS_IOBYTES(name) do { \
	__PRINT_FIELD_LINE(#name, name##_stats,  count); \
	__PRINT_FIELD_LINE(#name, name##_stats,  time); \
	__PRINT_FIELD_LINE(#name, name##_stats,  idle); \
	__PRINT_FIELD_LINE(#name, name##_stats,  inbytes); \
	__PRINT_FIELD_LINE(#name, name##_stats,  outbytes); \
} while(0);
#define SMBPROFILE_STATS_SECTION_END
#define SMBPROFILE_STATS_END
	SMBPROFILE_STATS_ALL_SECTIONS
#undef __PRINT_FIELD_LINE
#undef SMBPROFILE_STATS_START
#undef SMBPROFILE_STATS_SECTION_START
#undef SMBPROFILE_STATS_COUNT
#undef SMBPROFILE_STATS_TIME
#undef SMBPROFILE_STATS_BASIC
#undef SMBPROFILE_STATS_BYTES
#undef SMBPROFILE_STATS_IOBYTES
#undef SMBPROFILE_STATS_SECTION_END
#undef SMBPROFILE_STATS_END

	return True;
}

/* Convert microseconds to milliseconds. */
#define usec_to_msec(s) ((s) / 1000)
/* Convert microseconds to seconds. */
#define usec_to_sec(s) ((s) / 1000000)
/* One second in microseconds. */
#define one_second_usec (1000000)

#define sample_interval_usec one_second_usec

#define percent_time(used, period) ((double)(used) / (double)(period) * 100.0 )

static uint64_t print_count_count_samples(
	char *buf, const size_t buflen,
	const char *name,
	const struct smbprofile_stats_count * const current,
	const struct smbprofile_stats_count * const last,
	uint64_t delta_usec)
{
	uint64_t step = current->count - last->count;
	uint64_t count = 0;

	if (step != 0) {
		uint64_t delta_sec = usec_to_sec(delta_usec);

		count++;

		if (buf[0] == '\0') {
			snprintf(buf, buflen,
				"%-40s %ju/sec",
				name, (uintmax_t)(step / delta_sec));
		} else {
			printf("%-40s %s %ju/sec\n",
				buf, name, (uintmax_t)(step / delta_sec));
			buf[0] = '\0';
		}
	}

	return count;
}

static uint64_t print_basic_count_samples(
	char *buf, const size_t buflen,
	const char *name,
	const struct smbprofile_stats_basic * const current,
	const struct smbprofile_stats_basic * const last,
	uint64_t delta_usec)
{
	uint64_t step = current->count - last->count;
	uint64_t spent = current->time - last->time;
	uint64_t count = 0;

	if (step != 0) {
		uint64_t delta_sec = usec_to_sec(delta_usec);

		count++;

		if (buf[0] == '\0') {
			snprintf(buf, buflen,
				"%s %ju/sec (%.2f%%)",
				name, (uintmax_t)(step / delta_sec),
				percent_time(spent, delta_usec));
		} else {
			printf("%-40s %s %ju/sec (%.2f%%)\n",
				buf, name, (uintmax_t)(step / delta_sec),
				percent_time(spent, delta_usec));
			buf[0] = '\0';
		}
	}

	return count;
}

static uint64_t print_bytes_count_samples(
	char *buf, const size_t buflen,
	const char *name,
	const struct smbprofile_stats_bytes * const current,
	const struct smbprofile_stats_bytes * const last,
	uint64_t delta_usec)
{
	uint64_t step = current->count - last->count;
	uint64_t spent = current->time - last->time;
	uint64_t count = 0;

	if (step != 0) {
		uint64_t delta_sec = usec_to_sec(delta_usec);

		count++;

		if (buf[0] == '\0') {
			snprintf(buf, buflen,
				"%s %ju/sec (%.2f%%)",
				name, (uintmax_t)(step / delta_sec),
				percent_time(spent, delta_usec));
		} else {
			printf("%-40s %s %ju/sec (%.2f%%)\n",
				buf, name, (uintmax_t)(step / delta_sec),
				percent_time(spent, delta_usec));
			buf[0] = '\0';
		}
	}

	return count;
}

static uint64_t print_iobytes_count_samples(
	char *buf, const size_t buflen,
	const char *name,
	const struct smbprofile_stats_iobytes * const current,
	const struct smbprofile_stats_iobytes * const last,
	uint64_t delta_usec)
{
	uint64_t step = current->count - last->count;
	uint64_t spent = current->time - last->time;
	uint64_t count = 0;

	if (step != 0) {
		uint64_t delta_sec = usec_to_sec(delta_usec);

		count++;

		if (buf[0] == '\0') {
			snprintf(buf, buflen,
				"%s %ju/sec (%.2f%%)",
				name, (uintmax_t)(step / delta_sec),
				percent_time(spent, delta_usec));
		} else {
			printf("%-40s %s %ju/sec (%.2f%%)\n",
				buf, name, (uintmax_t)(step / delta_sec),
				percent_time(spent, delta_usec));
			buf[0] = '\0';
		}
	}

	return count;
}

static uint64_t print_count_samples(
	const struct profile_stats * const current,
	const struct profile_stats * const last,
	uint64_t delta_usec)
{
	uint64_t count = 0;
	char buf[60] = { '\0', };

	if (delta_usec == 0) {
		return 0;
	}

#define SMBPROFILE_STATS_START
#define SMBPROFILE_STATS_SECTION_START(name, display)
#define SMBPROFILE_STATS_COUNT(name) do { \
	count += print_count_count_samples(buf, sizeof(buf), \
					   #name, \
					   &current->values.name##_stats, \
					   &last->values.name##_stats, \
					   delta_usec); \
} while(0);
#define SMBPROFILE_STATS_TIME(name) do { \
} while(0);
#define SMBPROFILE_STATS_BASIC(name) do { \
	count += print_basic_count_samples(buf, sizeof(buf), \
					   #name, \
					   &current->values.name##_stats, \
					   &last->values.name##_stats, \
					   delta_usec); \
} while(0);
#define SMBPROFILE_STATS_BYTES(name) do { \
	count += print_bytes_count_samples(buf, sizeof(buf), \
					   #name, \
					   &current->values.name##_stats, \
					   &last->values.name##_stats, \
					   delta_usec); \
} while(0);
#define SMBPROFILE_STATS_IOBYTES(name) do { \
	count += print_iobytes_count_samples(buf, sizeof(buf), \
					     #name, \
					     &current->values.name##_stats, \
					     &last->values.name##_stats, \
					     delta_usec); \
} while(0);
#define SMBPROFILE_STATS_SECTION_END
#define SMBPROFILE_STATS_END
	SMBPROFILE_STATS_ALL_SECTIONS
#undef SMBPROFILE_STATS_START
#undef SMBPROFILE_STATS_SECTION_START
#undef SMBPROFILE_STATS_COUNT
#undef SMBPROFILE_STATS_TIME
#undef SMBPROFILE_STATS_BASIC
#undef SMBPROFILE_STATS_BYTES
#undef SMBPROFILE_STATS_IOBYTES
#undef SMBPROFILE_STATS_SECTION_END
#undef SMBPROFILE_STATS_END

	if (buf[0] != '\0') {
		printf("%-40s\n", buf);
		buf[0] = '\0';
	}

	return count;
}

static struct profile_stats	sample_data[2];
static uint64_t		sample_time[2];

bool status_profile_rates(bool verbose)
{
	uint64_t remain_usec;
	uint64_t next_usec;
	uint64_t delta_usec;

	int last = 0;
	int current = 1;
	int tmp;

	if (verbose) {
	    fprintf(stderr, "Sampling stats at %d sec intervals\n",
		    usec_to_sec(sample_interval_usec));
	}

	if (!profile_setup(NULL, True)) {
		fprintf(stderr,"Failed to initialise profile memory\n");
		return False;
	}

	smbprofile_collect(&sample_data[last]);
	for (;;) {
		sample_time[current] = profile_timestamp();
		next_usec = sample_time[current] + sample_interval_usec;

		/* Take a sample. */
		smbprofile_collect(&sample_data[current]);

		/* Rate convert some values and print results. */
		delta_usec = sample_time[current] - sample_time[last];

		if (print_count_samples(&sample_data[current],
			&sample_data[last], delta_usec)) {
			printf("\n");
		}

		/* Swap sampling buffers. */
		tmp = last;
		last = current;
		current = tmp;

		/* Delay until next sample time. */
		remain_usec = next_usec - profile_timestamp();
		if (remain_usec > sample_interval_usec) {
			fprintf(stderr, "eek! falling behind sampling rate!\n");
		} else {
			if (verbose) {
			    fprintf(stderr,
				    "delaying for %lu msec\n",
				    (unsigned long )usec_to_msec(remain_usec));
			}

			usleep(remain_usec);
		}

	}

	return True;
}
