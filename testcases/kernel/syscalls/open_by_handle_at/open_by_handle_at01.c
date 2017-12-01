/******************************************************************************
 *
 * Copyright (c) 2017 CTERA Networks.  All Rights Reserved.
 * Author: Amir Goldstein <amir73il@gmail.com>
 *
 * This program is free software;  you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY;  without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 * the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program;  if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * DESCRIPTION
 *  This test case will verify basic function of name_to_handle_at and
 *  open_by_handle_at added by kernel 2.6.39 or up.
 *
 *****************************************************************************/

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include "test.h"
#include "safe_macros.h"
#include "lapi/fcntl.h"
#include "open_by_handle_at.h"

static void setup(void);
static void cleanup(void);

char *TCID = "openat01";

static int dir_fd, fd;
static int fd_invalid = 100;
static int fd_atcwd = AT_FDCWD;

#define TEST_FILE "test_file"
#define TEST_DIR "test_dir/"

static char glob_path[256];

static struct test_case {
	int *dir_fd;
	const char *pathname;
	int exp_ret;
	int exp_encode_errno;
	int exp_decode_errno;
} test_cases[] = {
	{&dir_fd, TEST_FILE, 0, 0, 0},
	{&dir_fd, glob_path, 0, 0, 0},
	{&fd, TEST_FILE, -1, ENOTDIR, ESTALE},
	{&fd_invalid, TEST_FILE, -1, EBADF, EBADF},
	{&fd_atcwd, TEST_DIR TEST_FILE, 0, 0, 0}
};

int TST_TOTAL = ARRAY_SIZE(test_cases);

#define TEST_HANDLE_SZ 128

struct test_file_handle {
	unsigned int  handle_bytes;
	int           handle_type;
	unsigned char f_handle[TEST_HANDLE_SZ];
};

static void verify_open_by_handle(struct test_case *test)
{
	int mount_id;
	struct test_file_handle handle = { .handle_bytes = TEST_HANDLE_SZ };

	TEST(name_to_handle_at(*test->dir_fd, test->pathname, (void *)&handle,
			       &mount_id, 0));

	if ((test->exp_ret == -1 && TEST_RETURN != -1) ||
	    (test->exp_ret == 0 && TEST_RETURN < 0)) {
		tst_resm(TFAIL | TTERRNO,
		         "name_to_handle_at() returned %ldl, expected %d",
			 TEST_RETURN, test->exp_ret);
		return;
	}

	if (TEST_ERRNO != test->exp_encode_errno) {
		tst_resm(TFAIL | TTERRNO,
		         "name_to_handle_at() returned wrong errno, expected %s(%d)",
			 tst_strerrno(test->exp_encode_errno), test->exp_encode_errno);
		return;
	}

	tst_resm(TPASS | TTERRNO, "name_to_handle_at() returned %ld", TEST_RETURN);

	TEST(open_by_handle_at(*test->dir_fd, (void *)&handle, O_RDWR));

	if ((test->exp_ret == -1 && TEST_RETURN != -1) ||
	    (test->exp_ret == 0 && TEST_RETURN < 0)) {
		tst_resm(TFAIL | TTERRNO,
		         "open_by_handle_at() returned %ldl, expected %d",
			 TEST_RETURN, test->exp_ret);
		return;
	}

	if (TEST_RETURN > 0)
		SAFE_CLOSE(cleanup, TEST_RETURN);

	if (TEST_ERRNO != test->exp_decode_errno) {
		tst_resm(TFAIL | TTERRNO,
		         "open_by_handle_at() returned wrong errno, expected %s(%d)",
			 tst_strerrno(test->exp_decode_errno), test->exp_decode_errno);
		return;
	}

	tst_resm(TPASS | TTERRNO, "open_by_handle_at() returned %ld", TEST_RETURN);
}

int main(int ac, char **av)
{
	int lc;
	int i;

	tst_parse_opts(ac, av, NULL, NULL);

	setup();

	for (lc = 0; TEST_LOOPING(lc); lc++) {
		tst_count = 0;

		for (i = 0; i < TST_TOTAL; i++)
			verify_open_by_handle(test_cases + i);
	}

	cleanup();
	tst_exit();
}

static void setup(void)
{
	char *tmpdir;

	tst_sig(NOFORK, DEF_HANDLER, cleanup);

	tst_tmpdir();

	SAFE_MKDIR(cleanup, TEST_DIR, 0700);
	dir_fd = SAFE_OPEN(cleanup, TEST_DIR, O_DIRECTORY);
	fd = SAFE_OPEN(cleanup, TEST_DIR TEST_FILE, O_CREAT | O_RDWR, 0600);

	tmpdir = tst_get_tmpdir();
	snprintf(glob_path, sizeof(glob_path), "%s/" TEST_DIR TEST_FILE,
	         tmpdir);
	free(tmpdir);

	TEST_PAUSE;
}

static void cleanup(void)
{
	if (fd > 0 && close(fd))
		tst_resm(TWARN | TERRNO, "close(fd) failed");

	if (dir_fd > 0 && close(dir_fd))
		tst_resm(TWARN | TERRNO, "close(dir_fd) failed");

	tst_rmdir();
}
