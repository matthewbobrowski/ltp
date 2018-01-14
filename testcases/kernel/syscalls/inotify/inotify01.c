/*
 * Copyright (c) 2007 SWSoft.  All Rights Reserved.
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
 * Started by Andrew Vagin <avagin@sw.ru>
 *
 * DESCRIPTION
 *     Check that inotify work for a file
 *
 * ALGORITHM
 *     Execute sequence file's operation and check return events
 */
#include "config.h"

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include "tst_test.h"
#include "inotify.h"

#if defined(HAVE_SYS_INOTIFY_H)
#include <sys/inotify.h>

#define TST_TOTAL 7

#define EVENT_MAX 1024
/* size of the event structure, not counting name */
#define EVENT_SIZE  (sizeof (struct inotify_event))
/* reasonable guess as to size of 1024 events */
#define EVENT_BUF_LEN        (EVENT_MAX * (EVENT_SIZE + 16))

#define BUF_SIZE 256
static char fname[BUF_SIZE];
static char buf[BUF_SIZE];
static int fd, fd_notify;
static int wd, reap_wd;

static int event_set[EVENT_MAX];

static char event_buf[EVENT_BUF_LEN];

void verify_inotify(void)
{
	int tst_count = 0;

	/*
	 * generate sequence of events
	 */
	SAFE_CHMOD(fname, 0755);
	event_set[tst_count] = IN_ATTRIB;
	tst_count++;

	if ((fd = open(fname, O_RDONLY)) == -1) {
		tst_brk(TBROK | TERRNO,
			"open(%s, O_RDWR|O_CREAT,0700) failed", fname);
	}
	event_set[tst_count] = IN_OPEN;
	tst_count++;

	if (read(fd, buf, BUF_SIZE) == -1) {
		tst_brk(TBROK | TERRNO,
			"read(%d, buf, %d) failed", fd, BUF_SIZE);
	}
	event_set[tst_count] = IN_ACCESS;
	tst_count++;

	SAFE_CLOSE(fd);
	event_set[tst_count] = IN_CLOSE_NOWRITE;
	tst_count++;

	if ((fd = open(fname, O_RDWR | O_CREAT, 0700)) == -1) {
		tst_brk(TBROK,
			"open(%s, O_RDWR|O_CREAT,0700) failed", fname);
	}
	event_set[tst_count] = IN_OPEN;
	tst_count++;

	if (write(fd, buf, BUF_SIZE) == -1) {
		tst_brk(TBROK,
			"write(%d, %s, 1) failed", fd, fname);
	}
	event_set[tst_count] = IN_MODIFY;
	tst_count++;

	SAFE_CLOSE(fd);
	event_set[tst_count] = IN_CLOSE_WRITE;
	tst_count++;

	if (TST_TOTAL != tst_count) {
		tst_brk(TBROK,
			"TST_TOTAL and tst_count are not equal");
	}
	tst_count = 0;

	/*
	 * get list on events
	 */
	int len, i = 0, test_num = 0;
	if ((len = read(fd_notify, event_buf, EVENT_BUF_LEN)) < 0) {
		tst_brk(TBROK,
			"read(%d, buf, %zu) failed",
			fd_notify, EVENT_BUF_LEN);

	}

	/*
	 * check events
	 */
	while (i < len) {
		struct inotify_event *event;
		event = (struct inotify_event *)&event_buf[i];
		if (test_num >= TST_TOTAL) {
			tst_res(TFAIL,
				"get unnecessary event: wd=%d mask=%x "
				"cookie=%u len=%u",
				event->wd, event->mask,
				event->cookie, event->len);
		} else if (event_set[test_num] == event->mask) {
			if (event->cookie != 0) {
				tst_res(TFAIL,
					"get event: wd=%d mask=%x "
					"cookie=%u (expected 0) len=%u",
					event->wd, event->mask,
					event->cookie, event->len);
			} else {
				tst_res(TPASS, "get event: wd=%d "
					"mask=%x cookie=%u len=%u",
					event->wd, event->mask,
					event->cookie, event->len);
			}

		} else {
			tst_res(TFAIL, "get event: wd=%d mask=%x "
				"(expected %x) cookie=%u len=%u",
				event->wd, event->mask,
				event_set[test_num],
				event->cookie, event->len);
		}
		test_num++;
		i += EVENT_SIZE + event->len;
	}
	for (; test_num < TST_TOTAL; test_num++) {
		tst_res(TFAIL, "didn't get event: mask=%x",
			event_set[test_num]);

	}
}

static void setup(void)
{
	sprintf(fname, "tfile_%d", getpid());
	if ((fd = open(fname, O_RDWR | O_CREAT, 0700)) == -1) {
		tst_brk(TBROK | TERRNO,
			"open(%s, O_RDWR|O_CREAT,0700) failed", fname);
	}
	if ((write(fd, fname, 1)) == -1) {
		tst_brk(TBROK | TERRNO, "write(%d, %s, 1) failed",
			fd, fname);
	}

	/* close the file we have open */
	SAFE_CLOSE(fd);
	if ((fd_notify = myinotify_init()) < 0) {
		if (errno == ENOSYS) {
			tst_brk(TCONF,
				"inotify is not configured in this kernel.");
		} else {
			tst_brk(TBROK | TERRNO,
				"inotify_init failed");
		}
	}

	if ((wd = myinotify_add_watch(fd_notify, fname, IN_ALL_EVENTS)) < 0) {
		tst_brk(TBROK | TERRNO,
			"inotify_add_watch (%d, %s, IN_ALL_EVENTS) failed",
			fd_notify, fname);
		reap_wd = 1;
	};

}

static void cleanup(void)
{
	if (reap_wd && myinotify_rm_watch(fd_notify, wd) < 0) {
		tst_res(TWARN | TERRNO, "inotify_rm_watch (%d, %d) failed",
			fd_notify, wd);

	}

	if (fd_notify > 0 && close(fd_notify))
		tst_res(TWARN, "close(%d) failed", fd_notify);
}

static struct tst_test test = {
	.needs_tmpdir = 1,
	.setup = setup,
	.cleanup = cleanup,
	.test_all = verify_inotify,
};

#else
	TST_TEST_TCONF("system doesn't have required inotify support");
#endif
