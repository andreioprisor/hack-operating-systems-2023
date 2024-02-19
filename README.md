# Hackathon SO - 2023

## Implementation 
We will showcase our own implementation of this year's challenge

**IPC:**
For this file, we implemented simple functions to create and connect a socket and send & receive data using buffers.

Socket initialization:
```c
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket");
		return -1;
	}
	return fd;
```

Socket connection:
```c
    struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);
	
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		perror("connect socker err");
		return -1;
	}
```

Send and Receive data using buffers:
```c
    int rc = write(fd, buf, len);
	if (rc == -1) {
		perror("send");
		return -1;
	}

    int rc = read(fd, buf, len);
	if (rc == -1) {
		perror("recv");
		return -1;
	}
```

Close the socket:
```c
    int rc = shutdown(fd, SHUT_RDWR);
	if (rc == -1) {
		perror("close socket failed");
		return;
	}
```

This is a like a helper file to establish a connection between the client and the server. We used simple system calls and checked the return code for each one of them.

**SERVER:**

In this section, we will show a simple connection between a client and a server, from the server's perspective.

Firstly, we listen to a connection using some system calls, then we bind it to the socket path and then accept it:

```c
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
```

Then, we do the while loop:
    In there, we parse the command and separate it into words, the first one for the library path, the second for the executable command and the last word is the file path (if needed). Here we also do the parallelization part. We create a new process using `fork()` and then run each iteration on a different process. We run each command in the `lib_run()` part. That function is separated in some small other functions. The first function creates a temp file using the `mkstemp()` call. We use `dup2()` to redirect the standard output to that file.

```c
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
```

    Then, lib_load() comes into places. It opens and links the library in a lazy way, and handles any errors (if needed).

```c
    lib->handle = dlopen(lib->libname, RTLD_LAZY);
	if (!lib->handle) {
		if (lib->filename == NULL) {
			fprintf(stdout, "Error: %s %s could not be executed.\n", lib->libname, lib->funcname);
		} else {
			fprintf(stdout, "Error: %s %s %s could not be executed.\n", lib->libname, lib->funcname, lib->filename);
		}
		return -1;
	}
```

    The last step is to execute. We get the function using the `dlsym()` call and execute it with the help of the server.h made by you.

```c
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
```

Lastly, we free the memory and exit successfully (hope so).