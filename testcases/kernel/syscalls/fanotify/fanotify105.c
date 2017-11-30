/*
 * Copyright (c) 2017 CTERA Networks.  All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Further, this software is distributed without any warranty that it is
 * free of the rightful claim of any third person regarding infringement
 * or the like.  Any license provided herein, whether implied or
 * otherwise, applies only to this software file.  Patent licenses, if
 * any, provided herein do not apply to combinations of this program with
 * other software, or any other product whatsoever.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Started by Amir Goldstein <amir73il@gmail.com>
 *
 * DESCRIPTION
 *     Check that fanotify overflow event is properly generated.
 *     Fanotify super block watch uses the inotify max_queued_events
 *     to determine event queue size.
 *
 * ALGORITHM
 *     Change max_queued_events. Generate enough events without reading them
 *     and check that overflow event is generated after max_queued_events.
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

#ifndef FAN_EVENT_ON_SB
#define FAN_EVENT_ON_SB         0x01000000

#define FAN_EVENT_INFO_PARENT   0x100
#define FAN_EVENT_INFO_NAME     0x200
#define FAN_EVENT_INFO_FH       0x400
#endif
#define FAN_EVENT_INFO \
	(FAN_EVENT_INFO_PARENT | FAN_EVENT_INFO_NAME)


#define SYSFS_MAX_QUEUED_EVENTS "/proc/sys/fs/inotify/max_queued_events"
#define TEST_MAX_EVENTS 10

#define EVENT_MAX 1024
/* size of the event structure, not counting name */
#define EVENT_SIZE  (sizeof (struct fanotify_event_metadata))
/* reasonable guess as to size of 1024 events */
#define EVENT_BUF_LEN        (EVENT_MAX * EVENT_SIZE)

#define BUF_SIZE 256
#define TST_TOTAL 8

static char fname1[BUF_SIZE], fname2[BUF_SIZE];
static int fd, fd_notify;
static int store_max_events;

static char event_buf[EVENT_BUF_LEN];

#define MOUNT_NAME "mntpoint"
#define DIR_NAME   "test_dir"
#define FILE_NAME1 "test_file1"
#define FILE_NAME2 "test_file2"

static int mount_created;

void test01(void)
{
	int len, i = 0, nevents = 0;
	int overflow = 0;

	/*
	 * generate enough events to fill the queue
	 */
	for (i = 0; i < TEST_MAX_EVENTS; i++) {
		if (rename(fname1, fname2) == -1) {
			tst_brk(TBROK | TERRNO,
					"rename(%s, %s) failed",
					FILE_NAME1, FILE_NAME2);
		}
		if (rename(fname2, fname1) == -1) {
			tst_brk(TBROK | TERRNO,
					"rename(%s, %s) failed",
					FILE_NAME1, FILE_NAME2);
		}
	}

	/*
	 * Check events
	 */
	len = SAFE_READ(0, fd_notify, event_buf, EVENT_BUF_LEN);

	i = 0;
	while (i < len) {
		struct fanotify_event_metadata *event;

		event = (struct fanotify_event_metadata *)&event_buf[i];
		if (event->mask != IN_MOVED_FROM &&
		    event->mask != IN_MOVED_TO &&
		    event->mask != FAN_Q_OVERFLOW) {
			tst_res(TFAIL,
					"got event: mask=%llx (unexpected) "
					"pid=%u fd=%d",
					(unsigned long long)event->mask,
					(unsigned)event->pid, event->fd);
		} else if (event->mask == FAN_Q_OVERFLOW) {
			if (event->event_len != event->metadata_len ||
					event->pid != getpid() ||
					event->fd != -1) {
				tst_res(TFAIL,
						"invalid overflow event: "
						" mask=%llx pid=%u "
						"(expected %u) fd=%d",
						(unsigned long long)event->mask,
						(unsigned)event->pid,
						(unsigned)getpid(),
						event->fd);
			} else if ((int)(i + event->event_len) != len) {
				tst_res(TFAIL,
						"overflow event is not last");
			} else if (nevents == TEST_MAX_EVENTS) {
				tst_res(TPASS,
					    "got overflow after %d events", nevents);
			} else {
				tst_res(TFAIL,
					    "got overflow after %d events (expected %u)",
					    nevents, TEST_MAX_EVENTS);
			}
			overflow = 1;
		}
		if (event->fd >= 0)
			SAFE_CLOSE(event->fd);
		i += event->event_len;
		nevents++;
	}

	if (nevents <= TEST_MAX_EVENTS) {
		tst_res(TFAIL,
			    "got %d events (expected %u)",
			    nevents, TEST_MAX_EVENTS + 1);
	}
	if (!overflow) {
		tst_res(TFAIL,
			    "did not get overflow after %d events",
			    nevents);
	}
}

static void setup(void)
{
	SAFE_MKDIR(MOUNT_NAME, 0755);
	SAFE_MOUNT(MOUNT_NAME, MOUNT_NAME, "none", MS_BIND, NULL);
	mount_created = 1;

	SAFE_MKDIR(MOUNT_NAME"/"DIR_NAME, 0755);
	strcpy(fname1, MOUNT_NAME"/"DIR_NAME"/"FILE_NAME1);
	strcpy(fname2, MOUNT_NAME"/"DIR_NAME"/"FILE_NAME2);
	if ((fd = creat(fname1, 0755)) == -1) {
		tst_brk(TBROK | TERRNO,
				"creat(\"%s\", 755) failed", fname1);
	}
	SAFE_CLOSE(fd);

	/*
	 * Save system max_queued_events and set small value
	 */
	SAFE_FILE_SCANF(SYSFS_MAX_QUEUED_EVENTS, "%d", &store_max_events);
	SAFE_FILE_PRINTF(SYSFS_MAX_QUEUED_EVENTS, "%d", TEST_MAX_EVENTS);

	fd_notify = SAFE_FANOTIFY_INIT(FAN_CLASS_NOTIF | FAN_EVENT_INFO,
					O_RDONLY);

	if (fanotify_mark(fd_notify, FAN_MARK_ADD, FAN_OPEN |
			    IN_CREATE | IN_DELETE |
			    IN_MOVED_FROM | IN_MOVED_TO |
			    FAN_EVENT_ON_SB | FAN_ONDIR, AT_FDCWD,
			  MOUNT_NAME) < 0) {
		tst_brk(TBROK | TERRNO,
		    "fanotify_mark (%d, FAN_MARK_ADD, FAN_OPEN | "
		    "IN_CREATE | IN_DELETE | "
		    "IN_MOVED_FROM | IN_MOVED_TO | "
		    "FAN_EVENT_ON_SB | FAN_ONDIR, "
		    "AT_FDCWD, '"MOUNT_NAME"') "
		    "failed", fd_notify);
	}
}

static void cleanup(void)
{

	/*
	 * Restore system max_queued_events
	 */
	if (store_max_events)
		SAFE_FILE_PRINTF(SYSFS_MAX_QUEUED_EVENTS, "%d", store_max_events);

	/*
	 * Cleanup the mark
	 */
	if (fd_notify > 0 && fanotify_mark(fd_notify, FAN_MARK_FLUSH, 0,
			    AT_FDCWD, MOUNT_NAME) < 0) {
		tst_brk(TBROK | TERRNO,
		    "fanotify_mark (%d, FAN_MARK_FLUSH, 0,"
		    "AT_FDCWD, '"MOUNT_NAME"') failed",
		    fd_notify);
	}

	if (fd_notify > 0)
		SAFE_CLOSE(fd_notify);

	if (mount_created && tst_umount(MOUNT_NAME) < 0)
		tst_brk(TBROK | TERRNO, "umount failed");
}

static struct tst_test test = {
	.test_all = test01,
	.setup = setup,
	.cleanup = cleanup,
	.needs_tmpdir = 1,
	.needs_root = 1
};

#else
	TST_TEST_TCONF("system doesn't have required fanotify support");
#endif
