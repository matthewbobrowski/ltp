// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2018 Matthew Bobrowski. All Rights Reserved.
 *
 * Started by Matthew Bobrowski <mbobrowski@mbobrowski.org>
 *
 * DESCRIPTION
 *	Check that the newly introduced FAN_OPEN_EXEC flag work as
 *	expected. The idea is to generate a sequence of open related
 *	actions to ensure that the correct event flags are being set
 *	depending on what event mask was requested when the object was
 *	marked.
 */
#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "tst_test.h"
#include "fanotify.h"

#if defined(HAVE_SYS_FANOTIFY_H)
#include <sys/fanotify.h>

#define EVENT_MAX 1024
#define EVENT_SIZE (sizeof (struct fanotify_event_metadata))
#define EVENT_BUF_LEN (EVENT_MAX * EVENT_SIZE)

#define BUF_SIZE 256
#define TEST_APP "fanotify_child"

static pid_t child_pid;
static char fname[BUF_SIZE];
static volatile int fd_notify;
static char event_buf[EVENT_BUF_LEN];

static struct tcase {
	const char *tname;
	struct fanotify_mark_type mark;
	unsigned long long mask;
	unsigned int should_ignore;
	unsigned long long ignore_mask;
	unsigned long long event_set[EVENT_MAX];
} tcases[] = {
	{
		"inode mark, FAN_OPEN events",
		INIT_FANOTIFY_MARK_TYPE(INODE),
		FAN_OPEN,
		0,
		0,
		{FAN_OPEN, FAN_OPEN}
	},
	{
		"inode mark, FAN_OPEN_EXEC events",
		INIT_FANOTIFY_MARK_TYPE(INODE),
		FAN_OPEN_EXEC,
		0,
		0,
		{FAN_OPEN_EXEC}
	},
	{
		"inode mark, FAN_OPEN | FAN_OPEN_EXEC events",
		INIT_FANOTIFY_MARK_TYPE(INODE),
		FAN_OPEN | FAN_OPEN_EXEC,
		0,
		0,
		{FAN_OPEN, FAN_OPEN | FAN_OPEN_EXEC}
	},
	{
		"inode mark, FAN_OPEN events, ignore FAN_OPEN_EXEC",
		INIT_FANOTIFY_MARK_TYPE(INODE),
		FAN_OPEN,
		1,
		FAN_OPEN_EXEC,
		{FAN_OPEN, FAN_OPEN}
	},
	{
		"inode mark, FAN_OPEN_EXEC events, ignore FAN_OPEN",
		INIT_FANOTIFY_MARK_TYPE(INODE),
		FAN_OPEN_EXEC,
		1,
		FAN_OPEN,
		{FAN_OPEN_EXEC}
	}
};

static int generate_events(void)
{
	int fd, status;

	child_pid = SAFE_FORK();

	/*
	 * Generate a sequence of events
	 */
	if (child_pid == 0) {
		close(fd_notify);

		fd = SAFE_OPEN(fname, O_RDONLY);

		if (fd > 0)
			SAFE_CLOSE(fd);

		SAFE_EXECL(TEST_APP, TEST_APP, NULL);
		exit(1);
	}

	SAFE_WAITPID(child_pid, &status, 0);

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 1;
	return 0;
}

static int setup_mark(unsigned int n)
{
	unsigned int i = 0;
	struct tcase *tc = &tcases[n];
	struct fanotify_mark_type *mark = &tc->mark;
	const char *const files[] = {fname, TEST_APP};

	tst_res(TINFO, "Test #%d: %s", n, tc->tname);
	fd_notify = SAFE_FANOTIFY_INIT(FAN_CLASS_NOTIF, O_RDONLY);

	for (; i < ARRAY_SIZE(files); i++) {
		/* Setup normal mark on object */
		if (fanotify_mark(fd_notify, FAN_MARK_ADD | mark->flag, 
					tc->mask, AT_FDCWD, files[i]) < 0) {
			if (errno == EINVAL && tc->mask & FAN_OPEN_EXEC) {
				tst_res(TCONF,
					"FAN_OPEN_EXEC not supported in "
					"kernel?");
				return -1;	
			} else if (errno == EINVAL) {
				tst_brk(TCONF | TERRNO,
					"CONFIG_FANOTIFY_ACCESS_PERMISSIONS "
					"not configured in kernel?");
			}else {
				tst_brk(TBROK | TERRNO,
					"fanotify_mark(%d, FAN_MARK_ADD | %s, "
					"%llx, AT_FDCWD, %s) failed", fd_notify,
				       	mark->name, tc->mask, files[i]);
			}
		}

		/* Setup ignore mark on object */
		if (tc->should_ignore) {
			if (fanotify_mark(fd_notify, FAN_MARK_ADD | mark->flag 
						| FAN_MARK_IGNORED_MASK, 
						tc->ignore_mask, AT_FDCWD, 
						files[i]) < 0) {
				if (errno == EINVAL && 
					tc->ignore_mask & FAN_OPEN_EXEC) {
					tst_res(TCONF,
						"FAN_OPEN_EXEC not supported "
						"in kernel?");
					return -1;	
				} else if (errno == EINVAL) {
					tst_brk(TCONF | TERRNO,
						"CONFIG_FANOTIFY_ACCESS_"
						"PERMISSIONS not configured in "
						"kernel?");	
				} else {
					tst_brk(TBROK | TERRNO,
						"fanotify_mark (%d, "
						"FAN_MARK_ADD | %s "
						"| FAN_MARK_IGNORED_MASK, "
						"%llx, AT_FDCWD, %s) failed", 
						fd_notify, mark->name, 
						tc->ignore_mask, files[i]);
				}
			}
		}
	}

	return 0;
}

static void do_test(unsigned int n)
{
	int i = 0, len = 0;
	struct tcase *tc = &tcases[n];
	unsigned int event_num = 0;
	unsigned int expected_num = ARRAY_SIZE(tc->event_set);

	/* Place a mark on the object */	
	if (setup_mark(n) != 0)
		return;

	/* Generate events in child process */
	if (!generate_events())
		return;

	/* Read available events into buffer */
	len = SAFE_READ(0, fd_notify, event_buf + len, EVENT_BUF_LEN - len);

	/* Process events */
	while (i < len && event_num < expected_num) {
		struct fanotify_event_metadata *event;

		event = (struct fanotify_event_metadata *) &event_buf[i];

		if (event->mask != *(tc->event_set + event_num)) {
			tst_res(TFAIL,
				"Received event: mask=%llx, pid=%u (expected "
				"%u), fd=%d", (unsigned long long) event->mask,
				(unsigned) event->pid, (unsigned) child_pid,
				event->fd);
		} else if (event->pid != child_pid) {
			tst_res(TFAIL,
				"Received event: mask=%llx, pid=%u (expected "
				"%u), fd=%d", (unsigned long long) event->mask,
				(unsigned) event->pid, (unsigned) child_pid,
				event->fd);
		} else {
			tst_res(TPASS,
				"Received event: mask=%llx, pid=%u, fd=%d",
				(unsigned long long) event->mask, 
				(unsigned) event->pid, event->fd);
		}

		if (event->fd != FAN_NOFD)
			SAFE_CLOSE(event->fd);

		event_num++;
		i += event->event_len;
	}

	if (fd_notify > 0)
		SAFE_CLOSE(fd_notify);
}

static void do_setup(void)
{
	sprintf(fname, "fname_%d", getpid());
	SAFE_FILE_PRINTF(fname, "1");
}

static void do_cleanup(void)
{
	if (fd_notify > 0)
		SAFE_CLOSE(fd_notify);
}

static const char *const resource_files[] = {
	TEST_APP,
	NULL	
};

static struct tst_test test = {
	.setup = do_setup,
	.test = do_test,
	.tcnt = ARRAY_SIZE(tcases),
	.cleanup = do_cleanup,
	.forks_child = 1,
	.needs_root = 1,
	.resource_files = resource_files
};
#else
	TST_TEST_CONF("System does not contain required fanotify support");
#endif
