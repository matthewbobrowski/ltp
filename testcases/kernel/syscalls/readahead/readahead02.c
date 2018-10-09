// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2012 Linux Test Project, Inc.
 */

/*
 * functional test for readahead() syscall
 *
 * This test is measuring effects of readahead syscall.
 * It mmaps/reads a test file with and without prior call to readahead.
 *
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include "config.h"
#include "tst_test.h"
#include "lapi/syscalls.h"

#if defined(__NR_readahead)
static char testfile[PATH_MAX] = "testfile";
static const char drop_caches_fname[] = "/proc/sys/vm/drop_caches";
static const char meminfo_fname[] = "/proc/meminfo";
static size_t testfile_size = 64 * 1024 * 1024;
static char *opt_fsizestr;
static int pagesize;
static unsigned long cached_max;
static int ovl_mounted;

#define MNTPOINT        "mntpoint"
#define OVL_LOWER	MNTPOINT"/lower"
#define OVL_UPPER	MNTPOINT"/upper"
#define OVL_WORK	MNTPOINT"/work"
#define OVL_MNT		MNTPOINT"/ovl"
#define MIN_SANE_READAHEAD (4u * 1024u)

static const char mntpoint[] = MNTPOINT;

static struct tst_option options[] = {
	{"s:", &opt_fsizestr, "-s    testfile size (default 64MB)"},
	{NULL, NULL, NULL}
};

static struct tcase {
	const char *tname;
	int use_overlay;
	int use_fadvise;
} tcases[] = {
	{ "readahead on file", 0, 0 },
	{ "readahead on overlayfs file", 1, 0 },
	{ "POSIX_FADV_WILLNEED on file", 0, 1 },
	{ "POSIX_FADV_WILLNEED on overlayfs file", 1, 1 },
};

static int fadvise_willneed(int fd, off_t offset, size_t len)
{
	/* Should have the same effect as readahead() syscall */
	return posix_fadvise(fd, offset, len, POSIX_FADV_WILLNEED);
}

static int libc_readahead(int fd, off_t offset, size_t len)
{
	return readahead(fd, offset, len);
}

typedef int (*readahead_func_t)(int, off_t, size_t);
static readahead_func_t readahead_func = libc_readahead;

static int readahead_supported = 1;
static int fadvise_supported = 1;

static int check_ret(struct tcase *tc)
{
	if (TST_RET == 0)
		return 0;
	/* posix_fadvise returns error number (not in errno) */
	if (tc->use_fadvise && (TST_ERR = TST_RET) == EINVAL &&
	    (!tc->use_overlay || !fadvise_supported)) {
		fadvise_supported = 0;
		tst_res(TCONF, "fadvise not supported on %s",
			tst_device->fs_type);
	} else if (TST_ERR == EINVAL &&
		   (!tc->use_overlay || !readahead_supported)) {
		readahead_supported = 0;
		tst_res(TCONF, "readahead not supported on %s",
			tst_device->fs_type);
	} else {
		tst_res(TFAIL | TTERRNO, "%s failed on %s",
			tc->use_fadvise ? "fadvise" : "readahead",
			tc->use_overlay ? "overlayfs" : tst_device->fs_type);
	}
	return 1;
}

static int has_file(const char *fname, int required)
{
	struct stat buf;

	if (stat(fname, &buf) == -1) {
		if (errno != ENOENT)
			tst_brk(TBROK | TERRNO, "stat %s", fname);
		if (required)
			tst_brk(TCONF, "%s not available", fname);
		return 0;
	}
	return 1;
}

static void drop_caches(void)
{
	SAFE_FILE_PRINTF(drop_caches_fname, "1");
}

static unsigned long parse_entry(const char *fname, const char *entry)
{
	FILE *f;
	long value = -1;
	int ret;
	char *line = NULL;
	size_t linelen;

	f = fopen(fname, "r");
	if (f) {
		do {
			ret = getline(&line, &linelen, f);
			if (sscanf(line, entry, &value) == 1)
				break;
		} while (ret != -1);
		fclose(f);
	}
	return value;
}

static unsigned long get_bytes_read(void)
{
	char fname[128];
	char entry[] = "read_bytes: %lu";
	sprintf(fname, "/proc/%u/io", getpid());
	return parse_entry(fname, entry);
}

static unsigned long get_cached_size(void)
{
	char entry[] = "Cached: %lu";
	return parse_entry(meminfo_fname, entry);
}

static void create_testfile(int use_overlay)
{
	int fd;
	char *tmp;
	size_t i;

	sprintf(testfile, "%s/testfile", use_overlay ? OVL_MNT : MNTPOINT);
	tst_res(TINFO, "creating test file of size: %zu", testfile_size);
	tmp = SAFE_MALLOC(pagesize);

	/* round to page size */
	testfile_size = testfile_size & ~((long)pagesize - 1);

	fd = SAFE_CREAT(testfile, 0644);
	for (i = 0; i < testfile_size; i += pagesize)
		SAFE_WRITE(1, fd, tmp, pagesize);
	SAFE_FSYNC(fd);
	SAFE_CLOSE(fd);
	free(tmp);
}

/* read_testfile - mmap testfile and read every page.
 * This functions measures how many I/O and time it takes to fully
 * read contents of test file.
 *
 * @do_readahead: call readahead prior to reading file content?
 * @fname: name of file to test
 * @fsize: how many bytes to read/mmap
 * @read_bytes: returns difference of bytes read, parsed from /proc/<pid>/io
 * @usec: returns how many microsecond it took to go over fsize bytes
 * @cached: returns cached kB from /proc/meminfo
 */
static void read_testfile(int do_readahead, const char *fname, size_t fsize,
			  unsigned long *read_bytes, long *usec,
			  unsigned long *cached)
{
	int fd;
	size_t i = 0;
	long read_bytes_start;
	unsigned char *p, tmp;
	unsigned long time_start_usec, time_end_usec;
	unsigned long cached_start, max_ra_estimate = 0;
	off_t offset = 0;
	struct timeval now;

	fd = SAFE_OPEN(fname, O_RDONLY);

	if (do_readahead) {
		cached_start = get_cached_size();
		do {
			TEST(readahead_func(fd, offset, fsize - offset));
			if (TST_RET != 0) {
				SAFE_CLOSE(fd);
				return;
			}

			/* estimate max readahead size based on first call */
			if (!max_ra_estimate) {
				*cached = get_cached_size();
				if (*cached > cached_start) {
					max_ra_estimate = (1024 *
						(*cached - cached_start));
					tst_res(TINFO, "max ra estimate: %lu",
						max_ra_estimate);
				}
				max_ra_estimate = MAX(max_ra_estimate,
					MIN_SANE_READAHEAD);
			}

			i++;
			offset += max_ra_estimate;
		} while ((size_t)offset < fsize);
		tst_res(TINFO, "readahead calls made: %zu", i);
		*cached = get_cached_size();

		/* offset of file shouldn't change after readahead */
		offset = SAFE_LSEEK(fd, 0, SEEK_CUR);
		if (offset == 0)
			tst_res(TPASS, "offset is still at 0 as expected");
		else
			tst_res(TFAIL, "offset has changed to: %lu", offset);
	}

	if (gettimeofday(&now, NULL) == -1)
		tst_brk(TBROK | TERRNO, "gettimeofday failed");
	time_start_usec = now.tv_sec * 1000000 + now.tv_usec;
	read_bytes_start = get_bytes_read();

	p = SAFE_MMAP(NULL, fsize, PROT_READ, MAP_SHARED | MAP_POPULATE, fd, 0);

	/* for old kernels, where MAP_POPULATE doesn't work, touch each page */
	tmp = 0;
	for (i = 0; i < fsize; i += pagesize)
		tmp = tmp ^ p[i];
	/* prevent gcc from optimizing out loop above */
	if (tmp != 0)
		tst_brk(TBROK, "This line should not be reached");

	if (!do_readahead)
		*cached = get_cached_size();

	SAFE_MUNMAP(p, fsize);

	*read_bytes = get_bytes_read() - read_bytes_start;
	if (gettimeofday(&now, NULL) == -1)
		tst_brk(TBROK | TERRNO, "gettimeofday failed");
	time_end_usec = now.tv_sec * 1000000 + now.tv_usec;
	*usec = time_end_usec - time_start_usec;

	SAFE_CLOSE(fd);
}

static void test_readahead(unsigned int n)
{
	unsigned long read_bytes, read_bytes_ra;
	long usec, usec_ra;
	unsigned long cached_high, cached_low, cached, cached_ra;
	char proc_io_fname[128];
	struct tcase *tc = &tcases[n];

	tst_res(TINFO, "Test #%d: %s", n, tc->tname);

	sprintf(proc_io_fname, "/proc/%u/io", getpid());

	if (tc->use_overlay && !ovl_mounted) {
		tst_res(TCONF,
			"overlayfs is not configured in this kernel.");
		return;
	}

	create_testfile(tc->use_overlay);

	/* Use either readahead() syscall or POSIX_FADV_WILLNEED */
	readahead_func = tc->use_fadvise ? fadvise_willneed : libc_readahead;

	/* find out how much can cache hold if we read whole file */
	read_testfile(0, testfile, testfile_size, &read_bytes, &usec, &cached);
	cached_high = get_cached_size();
	sync();
	drop_caches();
	cached_low = get_cached_size();
	cached_max = MAX(cached_max, cached_high - cached_low);

	tst_res(TINFO, "read_testfile(0)");
	read_testfile(0, testfile, testfile_size, &read_bytes, &usec, &cached);
	if (cached > cached_low)
		cached = cached - cached_low;
	else
		cached = 0;

	sync();
	drop_caches();
	cached_low = get_cached_size();
	tst_res(TINFO, "read_testfile(1)");
	read_testfile(1, testfile, testfile_size, &read_bytes_ra,
		      &usec_ra, &cached_ra);
	if (check_ret(tc))
		return;
	if (cached_ra > cached_low)
		cached_ra = cached_ra - cached_low;
	else
		cached_ra = 0;

	tst_res(TINFO, "read_testfile(0) took: %ld usec", usec);
	tst_res(TINFO, "read_testfile(1) took: %ld usec", usec_ra);
	if (has_file(proc_io_fname, 0)) {
		tst_res(TINFO, "read_testfile(0) read: %ld bytes", read_bytes);
		tst_res(TINFO, "read_testfile(1) read: %ld bytes",
			read_bytes_ra);
		/* actual number of read bytes depends on total RAM */
		if (read_bytes_ra < read_bytes)
			tst_res(TPASS, "readahead saved some I/O");
		else
			tst_res(TFAIL, "readahead failed to save any I/O");
	} else {
		tst_res(TCONF, "Your system doesn't have /proc/pid/io,"
			" unable to determine read bytes during test");
	}

	tst_res(TINFO, "cache can hold at least: %ld kB", cached_max);
	tst_res(TINFO, "read_testfile(0) used cache: %ld kB", cached);
	tst_res(TINFO, "read_testfile(1) used cache: %ld kB", cached_ra);

	if (cached_max * 1024 >= testfile_size) {
		/*
		 * if cache can hold ~testfile_size then cache increase
		 * for readahead should be at least testfile_size/2
		 */
		if (cached_ra * 1024 > testfile_size / 2)
			tst_res(TPASS, "using cache as expected");
		else if (!cached_ra)
			tst_res(TFAIL, "readahead failed to use any cache");
		else
			tst_res(TWARN, "using less cache than expected");
	} else {
		tst_res(TCONF, "Page cache on your system is too small "
			"to hold whole testfile.");
	}
}

static void setup_overlay(void)
{
	int ret;

	/* Setup an overlay mount with lower dir and file */
	SAFE_MKDIR(OVL_LOWER, 0755);
	SAFE_MKDIR(OVL_UPPER, 0755);
	SAFE_MKDIR(OVL_WORK, 0755);
	SAFE_MKDIR(OVL_MNT, 0755);
	ret = mount("overlay", OVL_MNT, "overlay", 0, "lowerdir="OVL_LOWER
		    ",upperdir="OVL_UPPER",workdir="OVL_WORK);
	if (ret < 0) {
		if (errno == ENODEV) {
			tst_res(TINFO,
				"overlayfs is not configured in this kernel.");
			return;
		}
		tst_brk(TBROK | TERRNO, "overlayfs mount failed");
	}
	ovl_mounted = 1;
}

static void setup(void)
{
	if (opt_fsizestr)
		testfile_size = SAFE_STRTOL(opt_fsizestr, 1, INT_MAX);

	has_file(drop_caches_fname, 1);
	has_file(meminfo_fname, 1);

	/* check if readahead is supported */
	tst_syscall(__NR_readahead, 0, 0, 0);

	pagesize = getpagesize();

	setup_overlay();
}

static void cleanup(void)
{
	if (ovl_mounted)
		SAFE_UMOUNT(OVL_MNT);
}

static struct tst_test test = {
	.needs_root = 1,
	.needs_tmpdir = 1,
	.mount_device = 1,
	.mntpoint = mntpoint,
	.setup = setup,
	.cleanup = cleanup,
	.options = options,
	.test = test_readahead,
	.tcnt = ARRAY_SIZE(tcases),
};

#else /* __NR_readahead */
	TST_TEST_TCONF("System doesn't support __NR_readahead");
#endif
