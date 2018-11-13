// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2018 Matthew Bobrowski. All Rights Reserved.
 *
 * Started by Matthew Bobrowski <mbobrowski@mbobrowski.org>
 *
 * DESCRIPTION
 *	This set of tests is to ensure that the FAN_UNPRIVILEGED feature within
 *	fanotify is functioning as expected. The objective this test case file
 *	is to validate whether any forbidden flags that are passed in
 *	conjunction with FAN_UNPRIVILEGED return the correct error result.
 */
#define _GNU_SOURCE
#include "config.h"

#include <pwd.h>
#include <stdio.h>
#include <errno.h>
#include "tst_test.h"
#include "fanotify.h"

#if defined(HAVE_SYS_FANOTIFY_H)
#include <sys/fanotify.h>

#define BUF_SIZE 256

/*
 * This is a set of intialization flags that are not permitted to be used in
 * conjunction with FAN_UNPRIVILEGED. Thus, if supplied, either EPERM or EINVAL
 * should be returned to the calling process respectively.
 */
#define DISALLOWED_INIT_FLAGS	(FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS | \
				 FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT)

/*
 * This is a set of mark flags that are not permitted to be used in
 * conjunction with FAN_UNPRIVILEGED.
 */
#define DISALLOWED_MARK_FLAGS	(FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM)

static int fd_notify;
static char filename[BUF_SIZE];

static struct test_case_t {
	const char *name;
	unsigned long init_flags;
	unsigned long mark_flags;
	unsigned long long mark_mask;
} test_cases[] = {
	{
		"init_flags: FAN_UNPRIVILEGED | FAN_CLASS_CONTENT",
		FAN_UNPRIVILEGED | FAN_CLASS_CONTENT,
		0,
		0
	},
	{
		"init_flags: FAN_UNPRIVILEGED | FAN_CLASS_PRE_CONTENT",
		FAN_UNPRIVILEGED | FAN_CLASS_PRE_CONTENT,
		0,
		0
	},
	{
		"init_flags: FAN_UNPRIVILEGED | FAN_UNLIMITED_QUEUE",
		FAN_UNPRIVILEGED | FAN_UNLIMITED_QUEUE,
		0,
		0
	},
	{
		"init_flags: FAN_UNPRIVILEGED | FAN_UNLIMITED_MARKS",
		FAN_UNPRIVILEGED | FAN_UNLIMITED_MARKS,
		0,
		0
	},
	{
		"init_flags: FAN_UNPRIVILEGED | FAN_CLASS_NOTIF, "
		"mark_flags: FAN_MARK_ADD | FAN_MARK_MOUNT",
		FAN_UNPRIVILEGED | FAN_CLASS_NOTIF,
		FAN_MARK_ADD | FAN_MARK_MOUNT,
		FAN_ALL_EVENTS
	},
	{
		"init_flags: FAN_UNPRIVILEGED | FAN_CLASS_NOTIF, "
		"mark_flags: FAN_MARK_ADD | FAN_MARK_FILESYSTEM",
		FAN_UNPRIVILEGED | FAN_CLASS_NOTIF,
		FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
		FAN_ALL_EVENTS
	},
	{
		"init_flags: FAN_UNPRIVILEGED | FAN_CLASS_NOTIF, "
		"mark_flags: FAN_MARK_ADD, "
		"mark_mask: FAN_OPEN_PERM",
		FAN_UNPRIVILEGED | FAN_CLASS_NOTIF,
		FAN_MARK_ADD,
		FAN_OPEN_PERM
	},
	{
		"init_flags: FAN_UNPRIVILEGED | FAN_CLASS_NOTIF, "
		"mark_flags: FAN_MARK_ADD, "
		"mark_mask: FAN_ACCESS_PERM",
		FAN_UNPRIVILEGED | FAN_CLASS_NOTIF,
		FAN_MARK_ADD,
		FAN_ACCESS_PERM
	},
	{
		"init_flags: FAN_UNPRIVILEGED | FAN_CLASS_NOTIF, "
		"mark_flags: FAN_MARK_ADD, "
		"mark_mask: FAN_ALL_EVENTS",
		FAN_UNPRIVILEGED | FAN_CLASS_NOTIF,
		FAN_MARK_ADD,
		FAN_ALL_EVENTS
	}
};

static void do_setup(void)
{
	/* Relinquish privileged user */
	if (geteuid() == 0) {
		tst_res(TINFO,
			"Running as privileged user, revoking permissions.");
		struct passwd *nobody = SAFE_GETPWNAM("nobody");
		SAFE_SETUID(nobody->pw_uid);
	}

	sprintf(filename, "file_%d", getpid());
	SAFE_FILE_PRINTF(filename, "1");
}

static void do_test(unsigned int n)
{
	struct test_case_t *tc = &test_cases[n];

	tst_res(TINFO, "Test #%d %s", n, tc->name);

	/* Initialize fanotify */
	fd_notify = fanotify_init(tc->init_flags, O_RDONLY);

	if (fd_notify < 0) {
		/*
		 * EPERM is returned when FAN_UNPRIVILEGED is not supported by
		 * the current kernel.
		 */
		if (errno == EPERM) {
			tst_res(TCONF,
				"FAN_UNPRIVILEGED not supported by kernel?");
			return;
		} else if (errno == EINVAL &&
				tc->init_flags & DISALLOWED_INIT_FLAGS) {
				tst_res(TPASS,
					"Received result EINVAL, as expected");
				return;
		} else {
			tst_brk(TBROK | TERRNO,
				"fanotify_init(0x%lx, O_RDONLY) failed",
				tc->init_flags);
		}
	}

	/* Attempt to place mark on object */
	if (fanotify_mark(fd_notify, tc->mark_flags, tc->mark_mask, AT_FDCWD,
				filename) < 0) {
		/*
		 * Unprivileged users are only allowed to mark inodes and not
		 * permitted to use access permissions
		 */
		if (errno == EINVAL &&
			(tc->mark_flags & DISALLOWED_MARK_FLAGS ||
			 tc->mark_mask & FAN_ALL_PERM_EVENTS)) {
			tst_res(TPASS, "Received result EINVAL, as expected");
			return;
		}

		tst_brk(TBROK | TERRNO,
			"fanotify_mark(%d, %lx, %llx, AT_FDCWD, %s) "
			"failed",
			fd_notify,
			tc->mark_flags,
			tc->mark_mask,
			filename);
	}

	tst_res(TPASS,
		"fanotify_init() and fanotify_mark() returned successfully, "
		"as expected");
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
	.needs_tmpdir = 1
};

#else
	TST_TEST_CONF("System does not have required fanotify support");
#endif
