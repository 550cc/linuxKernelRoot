#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <iostream>

#include <sys/types.h>
#include <sys/socket.h>

#include "socket.hpp"
#include "su.h"
#include "pts.hpp"
#include "../testRoot/super_root.h"

#ifndef PATH_MAX
# define PATH_MAX 256
#endif


int quit_signals[] = { SIGALRM, SIGABRT, SIGHUP, SIGPIPE, SIGQUIT, SIGTERM, SIGINT, 0 };

static void usage(int status) {
	FILE *stream = (status == EXIT_SUCCESS) ? stdout : stderr;

	fprintf(stream,
		"Usage: su [options] [-] [user [argument...]]\n\n"
		"Options:\n"
		"  -c, --command COMMAND         pass COMMAND to the invoked shell\n"
		"  -h, --help                    display this help message and exit\n"
		"  -s, --shell SHELL             use SHELL instead of the default " DEFAULT_SHELL "\n");
	exit(status);
}

/*
 * Bionic's atoi runs through strtol().
 * Use our own implementation for faster conversion.
 */
int parse_int(const char *s) {
	int val = 0;
	char c;
	while ((c = *(s++))) {
		if (c > '9' || c < '0')
			return -1;
		val = val * 10 + c - '0';
	}
	return val;
}


static void sighandler(int sig) {
	restore_stdin();

	// Assume we'll only be called before death
	// See note before sigaction() in set_stdin_raw()
	//
	// Now, close all standard I/O to cause the pumps
	// to exit so we can continue and retrieve the exit
	// code
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	// Put back all the default handlers
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_DFL;
	for (int i = 0; quit_signals[i]; ++i) {
		sigaction(quit_signals[i], &act, nullptr);
	}
}

static void setup_sighandlers(void(*handler)(int)) {
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_handler = handler;
	for (int i = 0; quit_signals[i]; ++i) {
		sigaction(quit_signals[i], &act, nullptr);
	}
}


int connect_daemon() {
	sockaddr_un sun;
	socklen_t len = setup_sockaddr(&sun, DEFAULT_MAIN_SOCKET);
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (connect(fd, (struct sockaddr*) &sun, len)) {
		TRACE("No daemon is currently running!\n");
		exit(1);
	}
	return fd;
}

int su_client_main(int argc, char *argv[]) {
	std::string shell = DEFAULT_SHELL;
	std::string command;
	int uid = UID_ROOT;

	int opt;
	while ((opt = getopt(argc, argv, "c:")) != -1)
	{
		switch (opt)
		{
		case 'c':
			for (int i = optind - 1; i < argc; ++i) {
				if (!command.empty())
					command += ' ';
				command += argv[i];
			}
			optind = argc;
			break;
		case 'h':
			usage(EXIT_SUCCESS);
			break;
		case 's':
			shell = optarg;
		default:
			printf("Unknown command.\n");
			return 0;
			break;
		}
	}

	TRACE("input shell:%s\n", shell.c_str());
	TRACE("input command:%s\n", command.c_str());

	/* username or uid */
	if (optind < argc) {
		struct passwd *pw;
		pw = getpwnam(argv[optind]);
		if (pw)
			uid = pw->pw_uid;
		else
			uid = parse_int(argv[optind]);
		optind++;
	}

	char pts_slave[PATH_MAX];
	int ptmx, fd;

	// Connect to client
	fd = connect_daemon();

	TRACE("connect_daemon successful.\n");

	// Send su_request
	write_int(fd, uid);
	write_string(fd, shell);
	write_string(fd, command);

	TRACE("send done.\n");

	// Wait for ack from daemon
	if (read_int(fd)) {
		// Fast fail
		fprintf(stderr, "%s\n", strerror(EACCES));
		return EACCES;
	}

	// Determine which one of our streams are attached to a TTY
	int atty = 0;
	if (isatty(STDIN_FILENO))  atty |= ATTY_IN;
	if (isatty(STDOUT_FILENO)) atty |= ATTY_OUT;
	if (isatty(STDERR_FILENO)) atty |= ATTY_ERR;

	if (atty) {
		// We need a PTY. Get one.
		ptmx = pts_open(pts_slave, sizeof(pts_slave));
	}
	else {
		pts_slave[0] = '\0';
	}

	// Send pts_slave
	write_string(fd, pts_slave);

	// Send stdin
	send_fd(fd, (atty & ATTY_IN) ? -1 : STDIN_FILENO);
	// Send stdout
	send_fd(fd, (atty & ATTY_OUT) ? -1 : STDOUT_FILENO);
	// Send stderr
	send_fd(fd, (atty & ATTY_ERR) ? -1 : STDERR_FILENO);

	if (atty) {
		setup_sighandlers(sighandler);
		watch_sigwinch_async(STDOUT_FILENO, ptmx);
		pump_stdin_async(ptmx);
		pump_stdout_blocking(ptmx);
	}

	// Get the exit code
	int code = read_int(fd);
	close(fd);
	TRACE("exit code: %d\n", code);
	return code;
}
