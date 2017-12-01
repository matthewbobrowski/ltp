/*
 * Copyright (c) 2017 CTERA Networks.  All Rights Reserved.
 *
 * This program is free software;  you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifndef OPEN_BY_HANDLE_AT_H
#define OPEN_BY_HANDLE_AT_H

#include <sys/types.h>
#include "config.h"
#include "lapi/syscalls.h"

#if !defined(HAVE_OPEN_BY_HANDLE_AT)
struct file_handle;
int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags)
{
	return ltp_syscall(__NR_open_by_handle_at, mount_fd, handle, flags);
}
#endif

#if !defined(HAVE_NAME_TO_HANDLE_AT)
struct file_handle;
int name_to_handle_at(int dirfd, const char *pathname,
		      struct file_handle *handle, int *mount_id, int flags)
{
	return ltp_syscall(__NR_name_to_handle_at, dirfd, pathname, handle,
			   mount_id, flags);
}
#endif

#endif /* OPEN_BY_HANDLE_AT_H */
