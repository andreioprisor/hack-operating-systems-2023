// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"


int create_socket(void)
{
	/* TODO: Implement create_socket(). */
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket");
		return -1;
	}
	return fd;
}

int connect_socket(int fd)
{
	/* TODO: Implement connect_socket(). */
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);
	
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		perror("connect socker err");
		return -1;
	}

	return 0;
}

ssize_t send_socket(int fd, const char *buf, size_t len)
{
	/* TODO: Implement send_socket(). */
	int rc = write(fd, buf, len);
	if (rc == -1) {
		perror("send");
		return -1;
	}

	return rc;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	/* TODO: Implement recv_socket(). */
	int rc = read(fd, buf, len);
	if (rc == -1) {
		perror("recv");
		return -1;
	}

	return rc;
}

void close_socket(int fd)
{
	/* TODO: Implement close_socket(). */
	int rc = shutdown(fd, SHUT_RDWR);
	if (rc == -1) {
		perror("close socket failed");
		return;
	}

	close(fd);
}





