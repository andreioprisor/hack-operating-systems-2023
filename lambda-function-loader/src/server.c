// SPDX-License-Identifier: BSD-3-Clause

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "ipc.h"
#include "server.h"

#ifndef OUTPUT_TEMPLATE
#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
#endif

int fd;
char *tmp;

static int lib_prehooks(struct lib *lib)
{
	tmp = strdup(OUTPUT_TEMPLATE);
	fd = mkstemp(tmp);
	if (fd == -1) {
		perror("mkstemp failed");
		free(tmp);
		return -1;
	}

	lib->outputfile = tmp;

	int ret = dup2(fd, STDOUT_FILENO);
	if (ret < 0) {
		perror("dup2 failed");
		return -1;
	}

	return 0;
}

static int lib_load(struct lib *lib)
{
	lib->handle = dlopen(lib->libname, RTLD_LAZY);
	if (!lib->handle) {
		if (lib->filename == NULL) {
			fprintf(stdout, "Error: %s %s could not be executed.\n", lib->libname, lib->funcname);
		} else {
			fprintf(stdout, "Error: %s %s %s could not be executed.\n", lib->libname, lib->funcname, lib->filename);
		}
		return -1;
	}
	return 0;
}

static int lib_execute(struct lib *lib)
{
	if (lib->filename == NULL) {
		lambda_func_t func = (lambda_func_t)dlsym(lib->handle, lib->funcname);
		if (func == NULL) {
			fprintf(stdout, "Error: %s %s could not be executed.\n", lib->libname, lib->funcname);
			return -1;
		}
		lib->run = func;
		lib->run();
	} else {
		lambda_param_func_t p_func = (lambda_param_func_t)dlsym(lib->handle, lib->funcname);
		if (p_func == NULL) {
			fprintf(stdout, "Error: %s %s %s could not be executed.\n", lib->libname, lib->funcname, lib->filename);
			return -1;
		}
		lib->p_run = p_func;
		lib->p_run(lib->filename);
	}
	return 0;
}

static int lib_run(struct lib *lib)
{
	int err;

	err = lib_prehooks(lib);
	if (err)
		return err;

	err = lib_load(lib);
	if (err)
		return err;

	err = lib_execute(lib);
	if (err)
		return err;

	close(fd);
	return 0;
}

static int parse_command(const char *buf, char *name, char *func, char *params)
{
	int ret;

	ret = sscanf(buf, "%s %s %s", name, func, params);
	if (ret < 0)
		return -1;

	return ret;
}

int main(void)
{
	int rc;
	int listenfd, connectfd;
	struct lib lib;
	struct sockaddr_un addr, raddr;
	socklen_t raddrlen;
	char buffer[BUFSIZ];

	setvbuf(stdout, NULL, _IONBF, 0);

	/* Create socket. */
	listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listenfd == -1) {
		perror("Socket failed");
		return -1;
	}
	/* Bind socket to path. */
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);
	unlink(SOCKET_NAME);

	rc = bind(listenfd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc == -1)
	{
		perror("bind failed");
		return -1;
	}
	/* Put in listen mode. */
	rc = listen(listenfd, 10);
	if (rc == -1)
	{
		perror("listen failed");
		return -1;
	}

	while (1)
	{
		// Accept connection
		char name[BUFSIZE], func[BUFSIZE], params[BUFSIZE];
		memset(name, 0, BUFSIZE);
		memset(func, 0, BUFSIZE);
		memset(params, 0, BUFSIZE);
		memset(buffer, 0, BUFSIZE);
		connectfd = accept(listenfd, (struct sockaddr *)&raddr, &raddrlen);
		if (connectfd == -1)
		{
			perror("connection failed");
			return -1;
		}

		pid_t pid = fork();
		if (pid == -1)
		{
			perror("fork failed");
			close(connectfd);
			continue;
		}

		if (pid == 0)
		{
			// Child process
			/* Receive from client. */
			rc = recv_socket(connectfd, buffer, BUFSIZ);
			if (rc == -1)
			{
				perror("Read failed");
				exit(EXIT_FAILURE);
			}

			int r = parse_command(buffer, name, func, params);
			lib.outputfile = NULL;
			lib.libname = NULL;
			lib.funcname = NULL;
			lib.filename = NULL;
			switch (r)
			{
			case 1:
				lib.libname = name;
				lib.funcname = "run";
				break;
			case 2:
				lib.libname = name;
				lib.funcname = func;
				break;
			case 3:
				lib.libname = name;
				lib.funcname = func;
				lib.filename = params;
				break;
			default:
				break;
			}
			memset(buffer, 0, strlen(buffer));
			rc = lib_run(&lib);
			if(rc == -1){
				perror("lib_run failed");
			}
			memcpy(buffer, lib.outputfile, strlen(lib.outputfile));

			rc = send_socket(connectfd, buffer, strlen(buffer));

			if (rc == -1)
			{
				perror("write failed");
				return -1;
			}

			free(lib.handle);
			free(lib.libname);
			free(lib.funcname);
			free(lib.filename);
			free(lib.outputfile);
			free(tmp);

			close(connectfd);
			exit(EXIT_SUCCESS);
		}
		else
		{
			close(connectfd);
		}
	}

	return 0;
}
