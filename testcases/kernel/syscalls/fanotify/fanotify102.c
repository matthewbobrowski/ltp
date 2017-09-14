// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2018 CTERA Networks.  All Rights Reserved.
 *
 * Started by Amir Goldstein <amir73il@gmail.com>
 *
 * DESCRIPTION
 *     Check that fanotify dentry events work with an unprivileged
 *     fanotify listener
 */
#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include "tst_test.h"
#include "fanotify.h"

#if defined(HAVE_SYS_FANOTIFY_H)
#include <sys/fanotify.h>
#include <sys/inotify.h>


#define EVENT_MAX 1024
/* size of the event structure, not counting name */
#define EVENT_SIZE  (sizeof (struct fanotify_event_metadata))
/* reasonable guess as to size of 1024 events */
#define EVENT_BUF_LEN        (EVENT_MAX * EVENT_SIZE)

#define BUF_SIZE 256
#define TST_TOTAL 7

static char fname1[BUF_SIZE], fname2[BUF_SIZE];
static char dname1[BUF_SIZE], dname2[BUF_SIZE];
static int fd, fd_notify;

struct event_t {
	char name[BUF_SIZE];
	unsigned long long mask;
};
static struct event_t event_set[EVENT_MAX];

static char event_buf[EVENT_BUF_LEN];

#define DIR_NAME1 "test_dir1"
#define DIR_NAME2 "test_dir2"
#define FILE_NAME1 "test_file1"
#define FILE_NAME2 "test_file2"

void test01(void)
{
	int ret, len = 0, i = 0, test_num = 0;
	unsigned int stored_cookie = UINT_MAX;

	int tst_count = 0;

	SAFE_MKDIR(dname1, 0755);

	if (fanotify_mark(fd_notify, FAN_MARK_ADD,
			  IN_ATTRIB | IN_CREATE | IN_DELETE |
			  IN_MOVED_FROM | IN_MOVED_TO | IN_MOVE_SELF |
			  FAN_ONDIR, AT_FDCWD,
			  dname1) < 0) {
		tst_brk(TBROK | TERRNO,
			"fanotify_mark (%d, FAN_MARK_ADD, "
			"IN_ATTRIB | IN_CREATE | IN_DELETE | "
			"IN_MOVED_FROM | IN_MOVED_TO | IN_MOVE_SELF | "
			"FAN_ONDIR, "
			"AT_FDCWD, %s) "
			"failed", fd_notify, dname1);
	}

	/*
	 * generate sequence of events
	 */
	fd = SAFE_CREAT(fname1, 0755);
	event_set[tst_count].mask = IN_CREATE;
	strcpy(event_set[tst_count].name, FILE_NAME1);
	tst_count++;
	SAFE_CLOSE(fd);

	/*
	 * Get list of events so far. We get events here to avoid
	 * merging of following events with the previous ones.
	 * This is papering over a bug solved by -4.4.y fix:
	 * "fanotify: fix merge non-filename events with filename event"
	 * so test will fail on unpatched kernel instead of timing out.
	 */
	ret = SAFE_READ(0, fd_notify, event_buf + len,
			EVENT_BUF_LEN - len);
	len += ret;

	SAFE_CHMOD(fname1, 0755);
	event_set[tst_count].mask = IN_ATTRIB;
	strcpy(event_set[tst_count].name, FILE_NAME1);
	tst_count++;

	SAFE_RENAME(fname1, fname2);
	event_set[tst_count].mask = IN_MOVED_FROM;
	strcpy(event_set[tst_count].name, FILE_NAME1);
	tst_count++;
	event_set[tst_count].mask = IN_MOVED_TO;
	strcpy(event_set[tst_count].name, FILE_NAME2);
	tst_count++;

	SAFE_UNLINK(fname2);
	event_set[tst_count].mask = IN_DELETE;
	strcpy(event_set[tst_count].name, FILE_NAME2);
	tst_count++;

	/*
	 * Generate events on directory
	 */
	SAFE_CHMOD(dname1, 0755);
	event_set[tst_count].mask = IN_ISDIR | IN_ATTRIB;
	strcpy(event_set[tst_count].name, DIR_NAME1);
	tst_count++;

	SAFE_RENAME(dname1, dname2);
	event_set[tst_count].mask = IN_ISDIR | IN_MOVE_SELF;
	strcpy(event_set[tst_count].name, DIR_NAME2);
	tst_count++;

	SAFE_RMDIR(dname2);

	/*
	 * Cleanup the mark
	 */
	if (fanotify_mark(fd_notify, FAN_MARK_FLUSH, 0,
			  AT_FDCWD, dname1) < 0) {
		tst_brk(TBROK | TERRNO,
			"fanotify_mark (%d, FAN_MARK_FLUSH, 0,"
			"AT_FDCWD, %s) failed",
			fd_notify, dname1);
	}

	if (tst_count != TST_TOTAL) {
		tst_brk(TBROK, "tst_count and TST_TOTAL are not equal");
	}

	/*
	 * Check events
	 */
	ret = SAFE_READ(0, fd_notify, event_buf + len,
			EVENT_BUF_LEN - len);
	len += ret;

	while (i < len) {
		struct fanotify_event_metadata *event;

		event = (struct fanotify_event_metadata *)&event_buf[i];
		if (test_num >= TST_TOTAL) {
			tst_res(TFAIL,
				"get unnecessary event: mask=%llx "
				"pid=%u fd=%d",
				(unsigned long long)event->mask,
				(unsigned)event->pid, event->fd);
			event->mask = 0;
		} else if (event->event_len > event->metadata_len) {
			/* fanotify filename events should not be merged */
			if (event->mask != event_set[test_num].mask) {
				tst_res(TFAIL,
					"got event: mask=%llx (expected %llx) "
					"pid=%u fd=%d name='%s'",
					(unsigned long long)event->mask,
					event_set[test_num].mask,
					(unsigned)event->pid, event->fd,
					(char *)(event+1));
			} else if (strncmp(event_set[test_num].name,
					(char *)(event+1),
					event->event_len - event->metadata_len)) {
				tst_res(TFAIL,
					"got event: mask=%llx "
					"pid=%u fd=%d name='%s' expected(%s)",
					(unsigned long long)event->mask,
					(unsigned)event->pid, event->fd,
					(char *)(event+1),
					event_set[test_num].name);
			} else if (event->mask & IN_MOVE) {
				int fail = 0;

				/* check that rename cookie is unique */
				if (event->mask & IN_MOVED_FROM) {
					if ((unsigned)event->pid == stored_cookie)
						fail = 1;
					else
						stored_cookie = (unsigned)event->pid;
				} else if (event->mask & IN_MOVED_TO) {
					if ((unsigned)event->pid != stored_cookie)
						fail = 1;
				}
				if (!fail) {
					tst_res(TPASS,
						"got event: mask=%llx cookie=%u fd=%d name='%s'",
						(unsigned long long)event->mask,
						(unsigned)event->pid, event->fd,
						(char *)(event+1));
				} else {
					tst_res(TFAIL,
						"got event: mask=%llx cookie=%u (last=%u) fd=%d name='%s'",
						(unsigned long long)event->mask,
						(unsigned)event->pid, stored_cookie, event->fd,
						(char *)(event+1));
				}
			} else {
				tst_res(TPASS,
					"got event: mask=%llx pid=%u fd=%d name='%s'",
					(unsigned long long)event->mask,
					(unsigned)event->pid, event->fd,
					(char *)(event+1));
			}
		} else if (!(event->mask & event_set[test_num].mask)) {
			tst_res(TFAIL,
				"got event: mask=%llx (expected %llx) "
				"pid=%u fd=%d",
				(unsigned long long)event->mask,
				event_set[test_num].mask,
				(unsigned)event->pid, event->fd);
		} else if (event->pid != getpid()) {
			tst_res(TFAIL,
				"got event: mask=%llx pid=%u "
				"(expected %u) fd=%d",
				(unsigned long long)event->mask,
				(unsigned)event->pid,
				(unsigned)getpid(),
				event->fd);
		} else {
			tst_res(TPASS,
				"got event: mask=%llx pid=%u fd=%d",
				(unsigned long long)event->mask,
				(unsigned)event->pid, event->fd);
		}
		event->mask &= ~event_set[test_num].mask;
		/* No events left in current mask? Go for next event */
		if (event->mask == 0) {
			i += event->event_len;
			close(event->fd);
		}
		test_num++;
	}
	for (; test_num < TST_TOTAL; test_num++) {
		tst_res(TFAIL, "didn't get event: mask=%llx",
			event_set[test_num].mask);

	}
}

static void setup(void)
{
	sprintf(dname1, "%s", DIR_NAME1);
	sprintf(dname2, "%s", DIR_NAME2);
	sprintf(fname1, "%s/%s", dname1, FILE_NAME1);
	sprintf(fname2, "%s/%s", dname1, FILE_NAME2);
	fd_notify = SAFE_FANOTIFY_INIT(FAN_CLASS_NOTIF | FAN_UNPRIVILEGED,
				       O_RDONLY);
}

static void cleanup(void)
{
	if (fd_notify > 0)
		SAFE_CLOSE(fd_notify);
}

static struct tst_test test = {
	.test_all = test01,
	.setup = setup,
	.cleanup = cleanup,
	.needs_tmpdir = 1,
};

#else
	TST_TEST_TCONF("system doesn't have required fanotify support");
#endif
