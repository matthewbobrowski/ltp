// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2018 Matthew Bobrowski. All Rights Reserved.
 *
 * Started by Matthew Bobrowski <mbobrowski@mbobrowski.org>
 *
 * DESCRIPTION
 *	Validate that the values returned within an event when
 *	FAN_REPORT_FID is specified matches those that are obtained via
 *	explicit invocation to system calls statfs(2) and
 *	name_to_handle_at(2).
 */
#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "tst_test.h"
#include "fanotify.h"

#define PATH_LEN 128
#define BUF_SIZE 256
#define DIR_ONE "dir_one"
#define FILE_ONE "file_one"
#define FILE_TWO "file_two"
#define MOUNT_PATH "mntpoint"
#define EVENT_MAX ARRAY_SIZE(objects)
#define DIR_PATH_ONE MOUNT_PATH"/"DIR_ONE
#define FILE_PATH_ONE MOUNT_PATH"/"FILE_ONE
#define FILE_PATH_TWO MOUNT_PATH"/"FILE_TWO

struct event_t {
	__kernel_fsid_t fsid;
	struct file_handle handle;
	char buf[MAX_HANDLE_SZ];
};

static const char *const objects[] = {
	FILE_PATH_ONE,
	FILE_PATH_TWO,
	DIR_PATH_ONE
};

static struct test_case_t {
	struct fanotify_mark_type mark;
	unsigned long long mask;
	unsigned long long expected_mask;
} test_cases[] = {
	{
		INIT_FANOTIFY_MARK_TYPE(INODE),
		FAN_OPEN | FAN_CLOSE,
		FAN_OPEN | FAN_CLOSE_NOWRITE
	},
	{
		INIT_FANOTIFY_MARK_TYPE(INODE),
		FAN_OPEN | FAN_CLOSE | FAN_ONDIR,
		FAN_OPEN | FAN_CLOSE_NOWRITE | FAN_ONDIR
	},
	{
		INIT_FANOTIFY_MARK_TYPE(MOUNT),
		FAN_OPEN | FAN_CLOSE,
		FAN_OPEN | FAN_CLOSE_NOWRITE
	},
	{
		INIT_FANOTIFY_MARK_TYPE(MOUNT),
		FAN_OPEN | FAN_CLOSE | FAN_ONDIR,
		FAN_OPEN | FAN_CLOSE_NOWRITE | FAN_ONDIR
	},
	{
		INIT_FANOTIFY_MARK_TYPE(FILESYSTEM),
		FAN_OPEN | FAN_CLOSE,
		FAN_OPEN | FAN_CLOSE_NOWRITE
	},
	{
		INIT_FANOTIFY_MARK_TYPE(FILESYSTEM),
		FAN_OPEN | FAN_CLOSE | FAN_ONDIR,
		FAN_OPEN | FAN_CLOSE_NOWRITE | FAN_ONDIR
	}
};

static int fanotify_fd;
static char events_buf[BUF_SIZE];
static struct event_t event_set[EVENT_MAX];

static void do_setup(void)
{
	/* Create test files and directories */
	SAFE_MKDIR(DIR_PATH_ONE, 0755);
	SAFE_FILE_PRINTF(FILE_PATH_ONE, "0");
	SAFE_FILE_PRINTF(FILE_PATH_TWO, "0");
}

static void get_object_stats(void)
{
	int mount_id;
	unsigned int i;
	struct statfs stats;

	for (i = 0; i < ARRAY_SIZE(objects); i++) {
		if (statfs(objects[i], &stats) == -1)
			tst_brk(TBROK | TERRNO,
				"statfs(%s, ...) failed", objects[i]);
		memcpy(&event_set[i].fsid, &stats.f_fsid,
			sizeof(stats.f_fsid));

		event_set[i].handle.handle_bytes = MAX_HANDLE_SZ;
		if (name_to_handle_at(AT_FDCWD, objects[i],
					&event_set[i].handle,
					&mount_id, 0) == -1) {
			if (errno == EOPNOTSUPP) {
				tst_res(TCONF,
					"filesystem %s does not support file "
					"handles",
					tst_device->fs_type);
			}
			tst_brk(TBROK | TERRNO,
				"name_to_handle_at(AT_FDCWD, %s, ...) failed",
				objects[i]);
		}
	}
}

static int setup_marks(unsigned int fd, unsigned int number)
{
	unsigned int i;
	struct test_case_t *tc = &test_cases[number];
	struct fanotify_mark_type *mark = &tc->mark;

	for (i = 0; i < ARRAY_SIZE(objects); i++) {
		if (fanotify_mark(fd, FAN_MARK_ADD | mark->flag, tc->mask,
					AT_FDCWD, objects[i]) == -1) {
			if (errno == EINVAL &&
				mark->flag & FAN_MARK_FILESYSTEM) {
				tst_res(TCONF,
					"FAN_MARK_FILESYSTEM not supported by "
					"kernel");
				return 1;
			} else if (errno == ENODEV &&
					!event_set[i].fsid.val[0] &&
					event_set[i].fsid.val[1]) {
				tst_res(TCONF,
					"FAN_REPORT_FID not supported on "
					"filesystem type %s",
					tst_device->fs_type);
				return 1;
			}
			tst_brk(TBROK | TERRNO,
				"fanotify_mark(%d, FAN_MARK_ADD, FAN_OPEN, "
				"AT_FDCWD, %s) failed",
				fanotify_fd, FILE_PATH_ONE);
		}
	}
	return 0;
}

static void do_test(unsigned int number)
{
	unsigned int i;
	int len, fds[ARRAY_SIZE(objects)];

	struct file_handle *event_file_handle;
	struct fanotify_event_metadata *metadata;
	struct fanotify_event_info_fid *event_fid;
	struct test_case_t *tc = &test_cases[number];
	struct fanotify_mark_type *mark = &tc->mark;

	tst_res(TINFO,
		"Test #%d: FAN_REPORT_FID with mark flag: %s",
		number, mark->name);

	/* Gets the filesystem statistics and file handle for each object */
	get_object_stats();

	fanotify_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_FID, O_RDONLY);
	if (fanotify_fd == -1) {
		if (errno == EINVAL) {
			tst_res(TCONF,
				"FAN_REPORT_FID not supported by kernel");
			return;
		}
		tst_brk(TBROK | TERRNO,
			"fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_FID, "
			"O_RDONLY) failed");
	}

	/* Place marks on a set of objects */
	if (setup_marks(fanotify_fd, number) != 0)
		return;

	/* Generate sequence of FAN_OPEN events on objects */
	for (i = 0; i < ARRAY_SIZE(objects); i++)
		fds[i] = SAFE_OPEN(objects[i], O_RDONLY);

	/* Generate sequence of FAN_CLOSE_NO_WRITE events on objects */
	for (i = 0; i < ARRAY_SIZE(objects); i++) {
		if (fds[i] > 0)
			SAFE_CLOSE(fds[i]);
	}

	/* Read events from event queue */
	len = SAFE_READ(0, fanotify_fd, events_buf, BUF_SIZE);

	/* Iterate over event queue */
	for (i = 0, metadata = (struct fanotify_event_metadata *) events_buf;
		FAN_EVENT_OK(metadata, len);
		metadata = FAN_EVENT_NEXT(metadata, len), i++) {
		event_fid = (struct fanotify_event_info_fid *) (metadata + 1);
		event_file_handle = (struct file_handle *) event_fid->handle;

		/* File descriptor is redundant with FAN_REPORT_FID */
		if (metadata->fd != FAN_NOFD)
			tst_res(TFAIL,
				"Unexpectedly received file descriptor %d in "
				"event. Expected to get FAN_NOFD(%d)",
				metadata->fd, FAN_NOFD);

		/* Ensure that the correct mask has been reported in event */
		if (!(metadata->mask & tc->expected_mask))
			tst_res(TFAIL,
				"Unexpected mask received: %llx (expected: %x) "
				"in event",
				metadata->mask,
				FAN_OPEN | FAN_CLOSE);

		/* Verify handle_bytes returned in event */
		if (event_file_handle->handle_bytes
				!= event_set[i].handle.handle_bytes) {
			tst_res(TFAIL,
				"handle_bytes (%x) returned in event does not "
				"equal to handle_bytes (%x) returned in "
				"name_to_handle_at(2)",
				event_file_handle->handle_bytes,
				event_set[i].handle.handle_bytes);
			continue;
		}

		/* Verify handle_type returned in event */
		if (event_file_handle->handle_type !=
				event_set[i].handle.handle_type) {
			tst_res(TFAIL,
				"handle_type (%x) returned in event does not "
				"equal to handle_type (%x) returned in "
				"name_to_handle_at(2)",
				event_file_handle->handle_type,
				event_set[i].handle.handle_type);
			continue;
		}

		/* Verify file identifier f_handle returned in event */
		if (memcmp(event_file_handle->f_handle,
				event_set[i].handle.f_handle,
				event_set[i].handle.handle_bytes) != 0) {
			tst_res(TFAIL,
				"event_file_handle->f_handle does not match "
				"event_set[i].handle.f_handle returned in "
				"name_to_handle_at(2)");
			continue;
		}

		/* Verify filesystem ID fsid  returned in event */
		if (memcmp(&event_fid->fsid, &event_set[i].fsid,
				sizeof(event_set[i].fsid)) != 0) {
			tst_res(TFAIL,
				"event_fid.fsid != stat.f_fsid that was "
				"obtained via statfs(2)");
			continue;
		}

		tst_res(TPASS,
			"event in queue contained the same fid attribute "
			"values as obtained through manually invoking "
			"statfs(2) and name_to_handle_at(2) on filesystem "
			"object");
	}
}

static void do_cleanup(void)
{
	if (fanotify_fd > 0)
		SAFE_CLOSE(fanotify_fd);
}

static struct tst_test test = {
	.setup = do_setup,
	.test = do_test,
	.tcnt = ARRAY_SIZE(test_cases),
	.cleanup = do_cleanup,
	.needs_root = 1,
	.needs_tmpdir = 1,
	.mount_device = 1,
	.mntpoint = MOUNT_PATH,
	.all_filesystems = 1
};
