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
 *     Check that inotify work for a directory after drop caches
 *
 * ALGORITHM
 *     Add watch on a directory and drop caches dentry and inode cache.
 *     inotify pins the directory inode in cache, but not the dentry.
 *     Execute operations on directory and child and expect events to be
 *     reported on directory watch. This will fail if file system does
 *     not obtain the pinned inode to the new allocated dentry after drop
 *     caches.
 */

#include "config.h"

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <limits.h>
#include "tst_test.h"
#include "inotify.h"

#if defined(HAVE_SYS_INOTIFY_H)
#include <sys/inotify.h>

#define TST_TOTAL 4

#define EVENT_MAX 1024
/* size of the event structure, not counting name */
#define EVENT_SIZE  (sizeof (struct inotify_event))
/* reasonable guess as to size of 1024 events */
#define EVENT_BUF_LEN        (EVENT_MAX * (EVENT_SIZE + 16))

#define BUF_SIZE 256
static int fd, fd_notify, reap_wd;
static int wd;

struct event_t {
	char name[BUF_SIZE];
	unsigned int mask;
};

#define DIR_NAME "test_dir"
#define FILE_NAME1 "test_file1"
#define FILE_NAME2 "test_file2"

static struct event_t event_set[EVENT_MAX];

static char event_buf[EVENT_BUF_LEN];

static const char drop_caches_fname[] = "/proc/sys/vm/drop_caches";

static void drop_caches(void)
{
	int ret;
	FILE *f;

	f = fopen(drop_caches_fname, "w");
	if (f) {
		/* Drop inode and dentry caches */
		ret = fprintf(f, "2");
		fclose(f);
		if (ret < 1)
			tst_brk(TBROK, "Failed to drop caches");
	} else {
		tst_brk(TBROK, "Failed to open drop_caches");
	}
}

void verify_inotify(void)
{
	int tst_count = 0;

	/*
	 * generate sequence of events
	 */
	SAFE_CHMOD(".", 0755);
	event_set[tst_count].mask = IN_ISDIR | IN_ATTRIB;
	strcpy(event_set[tst_count].name, "");
	tst_count++;

	if ((fd = creat(FILE_NAME1, 0755)) == -1) {
		tst_brk(TBROK | TERRNO,
			"creat(\"%s\", 755) failed", FILE_NAME1);
	}

	event_set[tst_count].mask = IN_CREATE;
	strcpy(event_set[tst_count].name, FILE_NAME1);
	tst_count++;
	event_set[tst_count].mask = IN_OPEN;
	strcpy(event_set[tst_count].name, FILE_NAME1);
	tst_count++;

	SAFE_CLOSE(fd);
	event_set[tst_count].mask = IN_CLOSE_WRITE;
	strcpy(event_set[tst_count].name, FILE_NAME1);
	tst_count++;

	if (tst_count != TST_TOTAL) {
		tst_brk(TBROK,
			"tst_count and TST_TOTAL are not equal");
	}

	tst_count = 0;

	int len, i = 0, test_num = 0;
	if ((len = read(fd_notify, event_buf, EVENT_BUF_LEN)) == -1) {
		tst_brk(TBROK | TERRNO,
			"read(%d, buf, %zu) failed",
			fd_notify, EVENT_BUF_LEN);

	}

	while (i < len) {
		struct inotify_event *event;
		event = (struct inotify_event *)&event_buf[i];
		if (test_num >= TST_TOTAL) {
			tst_res(TFAIL,
				"get unnecessary event: "
				"wd=%d mask=%x cookie=%u len=%u"
				"name=\"%.*s\"", event->wd, event->mask,
				event->cookie, event->len, event->len,
				event->name);
		} else if ((event_set[test_num].mask == event->mask)
				&&
				(!strncmp
				 (event_set[test_num].name, event->name,
				  event->len))) {
			tst_res(TPASS,
				"get event: wd=%d mask=%x "
				"cookie=%u len=%u name=\"%.*s\"",
				event->wd, event->mask,
				event->cookie, event->len,
				event->len, event->name);
		} else {
			tst_res(TFAIL, "get event: wd=%d mask=%x "
				"(expected %x) cookie=%u len=%u "
				"name=\"%s\" (expected \"%s\") %d",
				event->wd, event->mask,
				event_set[test_num].mask,
				event->cookie, event->len, event->name,
				event_set[test_num].name,
				strcmp(event_set[test_num].name,
					event->name));
		}
		test_num++;
		i += EVENT_SIZE + event->len;
	}

	for (; test_num < TST_TOTAL; test_num++) {
		tst_res(TFAIL, "didn't get event: mask=%x ",
			event_set[test_num].mask);
	}
}

static void setup(void)
{
	struct stat buf;

	if ((fd_notify = myinotify_init()) < 0) {
		if (errno == ENOSYS) {
			tst_brk(TCONF,
				"inotify is not configured in this kernel.");
		} else {
			tst_brk(TBROK | TERRNO,
				"inotify_init () failed");
		}
	}

	SAFE_MKDIR(DIR_NAME, 0755);
	SAFE_STAT(DIR_NAME, &buf);
	tst_res(TINFO, DIR_NAME " ino=%lu", buf.st_ino);

	if ((wd = myinotify_add_watch(fd_notify, DIR_NAME, IN_ALL_EVENTS)) < 0) {
		tst_brk(TBROK | TERRNO,
			"inotify_add_watch (%d, " DIR_NAME ", IN_ALL_EVENTS) failed",
			fd_notify);
		reap_wd = 1;
	};

	drop_caches();

	SAFE_STAT(DIR_NAME, &buf);
	tst_res(TINFO, DIR_NAME " ino=%lu", buf.st_ino);

	SAFE_CHDIR(DIR_NAME);
}

static void cleanup(void)
{
	if (reap_wd && myinotify_rm_watch(fd_notify, wd) < 0) {
		tst_res(TWARN,
			"inotify_rm_watch (%d, %d) failed,", fd_notify, wd);

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
