// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2021 Google. All Rights Reserved.
 *
 * Started by Matthew Bobrowski <repnop@google.com>
 */

/*\
 * [Description]
 *
 * A test which verifies whether the returned struct
 * fanotify_event_info_pidfd in FAN_REPORT_PIDFD mode contains the
 * expected set of information.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "tst_test.h"
#include "tst_safe_stdio.h"
#include "lapi/pidfd_open.h"

#ifdef HAVE_SYS_FANOTIFY_H
#include "fanotify.h"

#define BUF_SZ		4096
#define MOUNT_PATH	"fs_mnt"
#define TEST_FILE	MOUNT_PATH "/testfile"

struct pidfd_fdinfo_t {
	int pos;
	int flags;
	int mnt_id;
	int pid;
	int ns_pid;
};

static int fanotify_fd;
static char event_buf[BUF_SZ];
static struct pidfd_fdinfo_t *self_pidfd_fdinfo = NULL;

static char *trim(char *line)
{
	char *start = line;
	char *end = line + strlen(line);

	while(*start && isspace(*start))
		start++;

	while(end > start && isspace(*(end - 1)))
		end--;

	*end = '\0';
	return start;
}

static int parse_pidfd_fdinfo_line(char *line,
				   struct pidfd_fdinfo_t *pidfd_fdinfo)
{
	char *ptr, *key, *value;

	ptr = strchr(line, ':');
	if (ptr == NULL)
		return -1;

	*ptr++ = '\0';
	key = trim(line);
	value = trim(ptr);

	/*
	 * Ensure to cover all the keys found within a pidfd
	 * fdinfo. If we encounter an unexpected key, report that as
	 * an error and return control to the caller.
	 */
	if (strcmp(key, "pos") == 0)
		pidfd_fdinfo->pos = atoi(value);
	else if (strcmp(key, "flags") == 0)
		pidfd_fdinfo->flags = (int)strtol(value, NULL, 16);
	else if (strcmp(key, "mnt_id") == 0)
		pidfd_fdinfo->mnt_id = atoi(value);
	else if (strcmp(key, "Pid") == 0)
		pidfd_fdinfo->pid = atoi(value);
	else if (strcmp(key, "NSpid") == 0)
		pidfd_fdinfo->ns_pid = atoi(value);
	else
		return -1;

	return 0;
}

static struct pidfd_fdinfo_t *read_pidfd_fdinfo(int pidfd)
{
	FILE *f;
	size_t len;
	char *line = NULL, *fdinfo_path;
	struct pidfd_fdinfo_t *pidfd_fdinfo;

	pidfd_fdinfo = SAFE_MALLOC(sizeof(struct pidfd_fdinfo_t));

	SAFE_ASPRINTF(&fdinfo_path, "/proc/self/fdinfo/%d", pidfd);

	f = SAFE_FOPEN(fdinfo_path, "r");

	while (getline(&line, &len, f) != -1) {
		if (parse_pidfd_fdinfo_line(line, pidfd_fdinfo)) {
			pidfd_fdinfo = NULL;
			break;
		}
	}

	free(line);
	free(fdinfo_path);
	SAFE_FCLOSE(f);

	return pidfd_fdinfo;
}

static void do_setup(void)
{
	int ret, pidfd;

	SAFE_TOUCH(TEST_FILE, 0666, NULL);

	/*
	 * An explicit check for FAN_REPORT_PIDFD is performed early
	 * on in the test initialization as it's a prerequisite for
	 * all test cases.
	 */
	if ((ret = fanotify_init_flags_supported_by_kernel(FAN_REPORT_PIDFD))) {
		fanotify_init_flags_err_msg("FAN_REPORT_PIDFD", __FILE__,
					    __LINE__, tst_brk_, ret);
	}

	fanotify_fd = SAFE_FANOTIFY_INIT(FAN_REPORT_PIDFD, O_RDONLY);
	SAFE_FANOTIFY_MARK(fanotify_fd, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD,
			   TEST_FILE);

	pidfd = pidfd_open(getpid(), 0);
	if (pidfd < 0) {
		tst_brk(TBROK | TERRNO,
			"pidfd=%d, pidfd_open(%d, 0) failed",
			pidfd, getpid());
	}

	self_pidfd_fdinfo = read_pidfd_fdinfo(pidfd);
	if (self_pidfd_fdinfo == NULL) {
		tst_brk(TBROK,
			"pidfd=%d, failed to read pidfd fdinfo",
			pidfd);
	}
}

static void do_test(void)
{
	int i = 0, fd, len;

	/* Generate a single FAN_OPEN event on the watched object. */
	fd = SAFE_OPEN(TEST_FILE, O_RDONLY);
	SAFE_CLOSE(fd);

	/*
	 * Read all of the queued events into the provided event
	 * buffer.
	 */
	len = SAFE_READ(0, fanotify_fd, event_buf, sizeof(event_buf));
	while(i < len) {
		struct fanotify_event_metadata *event;
		struct fanotify_event_info_pidfd *info;
		struct pidfd_fdinfo_t *event_pidfd_fdinfo = NULL;

		event = (struct fanotify_event_metadata *)&event_buf[i];
		info = (struct fanotify_event_info_pidfd *)(event + 1);

		if (info->hdr.info_type != FAN_EVENT_INFO_TYPE_PIDFD) {
			tst_res(TFAIL,
				"unexpected info_type received in info "
				"header (expected: %d, got: %d",
				FAN_EVENT_INFO_TYPE_PIDFD,
				info->hdr.info_type);
			goto next_event;
		}

		if (info->hdr.len !=
		    sizeof(struct fanotify_event_info_pidfd)) {
			tst_res(TFAIL,
				"unexpected info object length "
				"(expected: %lu, got: %d",
				sizeof(struct fanotify_event_info_pidfd),
				info->hdr.len);
			goto next_event;
		}

		if (info->pidfd == FAN_EPIDFD) {
			tst_brk(TBROK,
				"in kernel pidfd creation failed for pid: %u, "
				"pidfd set to the value of: %d",
				(unsigned)event->pid,
				FAN_EPIDFD);
			goto next_event;
		} else if (info->pidfd == FAN_NOPIDFD) {
			tst_res(TPASS,
				"pid: %u terminated before pidfd creation, "
				"pidfd set to the value of: %d, as expected" ,
				(unsigned)event->pid,
				FAN_NOPIDFD);
			goto next_event;
		} else {
			event_pidfd_fdinfo = read_pidfd_fdinfo(info->pidfd);
			if (event_pidfd_fdinfo == NULL) {
				tst_brk(TBROK,
					"reading fdinfo for pidfd: %d "
					"describing pid: %u failed",
					info->pidfd,
					(unsigned)event->pid);
				goto next_event;
			}
		}

		if (event_pidfd_fdinfo->pid != event->pid) {
			tst_res(TFAIL,
				"pidfd provided for incorrect pid "
				"(expected pidfd for pid: %u, got pidfd for "
				"pid: %u)",
				(unsigned)event->pid,
				(unsigned)event_pidfd_fdinfo->pid);
			goto next_event;
		}

		if (memcmp(event_pidfd_fdinfo, self_pidfd_fdinfo,
		           sizeof(struct pidfd_fdinfo_t))) {
			tst_res(TFAIL,
				"pidfd fdinfo values for self and event differ "
				"(expected pos: %d, flags: %x, mnt_id: %d, "
				"pid: %d, ns_pid: %d, got pos: %d, "
				"flags: %x, mnt_id: %d, pid: %d, ns_pid: %d",
				self_pidfd_fdinfo->pos,
				self_pidfd_fdinfo->flags,
				self_pidfd_fdinfo->mnt_id,
				self_pidfd_fdinfo->pid,
				self_pidfd_fdinfo->ns_pid,
				event_pidfd_fdinfo->pos,
				event_pidfd_fdinfo->flags,
				event_pidfd_fdinfo->mnt_id,
				event_pidfd_fdinfo->pid,
				event_pidfd_fdinfo->ns_pid);
			goto next_event;
		}

		tst_res(TPASS,
			"got an event with the correct pidfd info record, "
			"mask: %lld, pid: %u, fd: %d, "
			"pidfd: %d, info_type: %d, info_len: %d",
			(unsigned long long)event->mask,
			(unsigned)event->pid,
			event->fd,
			info->pidfd,
			info->hdr.info_type,
			info->hdr.len);

next_event:
		i += event->event_len;
		if (event->fd >= 0)
			SAFE_CLOSE(event->fd);

		if (info->pidfd >= 0)
			SAFE_CLOSE(info->pidfd);

		if (event_pidfd_fdinfo)
			free(event_pidfd_fdinfo);
	}
}

static void do_cleanup(void)
{
	if (fanotify_fd >= 0)
		SAFE_CLOSE(fanotify_fd);

	if (self_pidfd_fdinfo)
		free(self_pidfd_fdinfo);
}

static struct tst_test test = {
	.setup = do_setup,
	.test_all = do_test,
	.cleanup = do_cleanup,
	.all_filesystems = 1,
	.needs_root = 1,
	.mntpoint = MOUNT_PATH,
};

#else
	TST_TEST_TCONF("system doesn't have required fanotify support");
#endif /* HAVE_SYS_FANOTIFY_H */
