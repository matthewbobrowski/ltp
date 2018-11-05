// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2018 Matthew Bobrowski. All Rights Reserved.
 *
 * Started by Matthew Bobrowski <mbobrowski@mbobrowski.org>
 *
 * DESCRIPTION
 *	This set of tests is to ensure that the FAN_UNPRIVILEGED feature within
 *	fanotify is functioning as expected. The objective of this test file is
 *	to generate a sequence of events and ensure that the returned events
 *	contain the limited values that a FAN_UNPRIVILEGED listener is expected
 *	to receive.
 */
#define _GNU_SOURCE
#include "config.h"

#include <pwd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "tst_test.h"
#include "fanotify.h"

#if defined(HAVE_SYS_FANOTIFY_H)
#include <sys/fanotify.h>

#define EVENT_MAX 1024
#define EVENT_SIZE (sizeof (struct fanotify_event_metadata))
#define EVENT_BUF_LEN (EVENT_MAX * EVENT_SIZE)
#define EVENT_SET_MAX 96

#define BUF_SIZE 256

static int fd_notify;
static char buf[BUF_SIZE];
static char filename[BUF_SIZE];
static char event_buf[EVENT_BUF_LEN];

static struct test_case_t {
	const char *name;
	unsigned int init_flags;
	unsigned int event_count;
	unsigned long long event_set[EVENT_SET_MAX];
} test_cases[] = {
	{
		"init flags: FAN_UNPRIVILEGED, mask: FAN_ALL_EVENTS",
		FAN_CLASS_NOTIF | FAN_UNPRIVILEGED,
		8,
		{
			FAN_OPEN,	/* Events in parent process */
			FAN_ACCESS,
			FAN_MODIFY,
			FAN_CLOSE,
			FAN_OPEN,	/* Events in child process */
			FAN_ACCESS,
			FAN_MODIFY,
			FAN_CLOSE
		}
	}
};

static void generate_events(void)
{
	int fd;

	/* FAN_OPEN */
	fd = SAFE_OPEN(filename, O_RDWR);

	/* FAN_ACCESS */
	SAFE_READ(0, fd, buf, BUF_SIZE);

	/* FAN_MODIFY */
	SAFE_WRITE(1, fd, filename, 1);

	/* FAN_CLOSE */
	if (fd > 0)
		SAFE_CLOSE(fd);
}

static int do_fork(void)
{
	int status;
	pid_t child;

	child = SAFE_FORK();

	if (child == 0) {
		close(fd_notify);
		generate_events();
		exit(0);
	}

	SAFE_WAITPID(child, &status, 0);

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;
	return 1;
}

static void do_setup(void)
{
	/* Relinquish privileged user */
	if (geteuid() == 0) {
		tst_res(TINFO,
			"Running as privileged user, revoking.");
		struct passwd *nobody = SAFE_GETPWNAM("nobody");
		SAFE_SETUID(nobody->pw_uid);
	}

	sprintf(filename, "file_%d", getpid());
	SAFE_FILE_PRINTF(filename, "1");
}

static void do_test(unsigned int n)
{
	int i = 0, len = 0; 
	pid_t pid = getpid();
	unsigned int test_number = 0;
	struct test_case_t *tc = &test_cases[n];

	tst_res(TINFO, "Test #%d %s", n, tc->name);

	/* Initialize fanotify */
	fd_notify = fanotify_init(tc->init_flags, O_RDONLY);

	if (fd_notify < 0) {
		if (errno == EPERM && tc->init_flags & FAN_UNPRIVILEGED) {
			tst_res(TCONF,
				"FAN_UNPRIVILEGED not supported by kernel?");
			return;
		} else {
			tst_brk(TBROK | TERRNO,
				"fanotify_init(0x%x, O_RDONLY) failed",
				tc->init_flags);
		}
	}

	/* Place mark on object */
	if (fanotify_mark(fd_notify, FAN_MARK_ADD, FAN_ALL_EVENTS, 
				AT_FDCWD, filename) < 0) {
		tst_res(TBROK | TERRNO,
			"fanotify_mark(%d, FAN_MARK_ADD, %d, "
			"AT_FDCWD, %s) failed",
			fd_notify,
			FAN_ALL_EVENTS,
			filename);
		return;
	}

	/* Generate sequence of events in current process */	
	generate_events();

	/* Generate sequence of events in child process */
	if (do_fork())
		goto cleanup;
	
	/* Read events from queue */
	len = SAFE_READ(0, fd_notify, event_buf + len, EVENT_BUF_LEN - len);

	/* Iterate over and validate events against expected result set */
	while (i < len && test_number < tc->event_count) {
		struct fanotify_event_metadata *event;

		event = (struct fanotify_event_metadata *) &event_buf[i];

		if (!(event->mask & tc->event_set[test_number])) {
			tst_res(TFAIL,
				"Received unexpected event mask: mask=%llx "
				"pid=%u fd=%d",
				(unsigned long long) event->mask,
				(unsigned) event->pid,
				event->fd);
		} else if (event->pid != pid && event->pid != 0) {
			tst_res(TFAIL,
				"Received unexpected pid in event: "
				"mask=%llx pid=%u (expected %u) fd=%d",
				(unsigned long long) event->mask,
				(unsigned) event->pid,
				pid,
				event->fd);	
		} else if (event->fd != FAN_NOFD) {
			tst_res(TFAIL,
				"Received unexpected file descriptor: "
				"mask=%llx pid=%u fd=%d (expected %d)",
				(unsigned long long) event->pid,
				(unsigned) event->pid,
				event->fd,
				FAN_NOFD);
		} else {
			tst_res(TPASS,
				"Received event: mask=%llx, pid=%u fd=%d",
				(unsigned long long) event->mask,
				(unsigned) event->pid,
				event->fd);
		}

		/* Non-permission events can be merged into a single event. */
		event->mask &= ~tc->event_set[test_number];
		
		if (event->mask == 0) 
			i += event->event_len;
		test_number++;
	}

cleanup:
	if (fd_notify > 0)
		SAFE_CLOSE(fd_notify);
}

static void do_cleanup(void)
{
	if (fd_notify > 0)
		SAFE_CLOSE(fd_notify);
}

static struct tst_test test = {
	.setup = do_setup,
	.test = do_test,
	.tcnt = ARRAY_SIZE(test_cases),
	.cleanup = do_cleanup,
	.forks_child = 1,
	.needs_tmpdir = 1
};

#else
	TST_TEST_CONF("System does not have required fanotify support");
#endif
