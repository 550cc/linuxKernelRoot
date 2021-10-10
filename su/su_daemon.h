#include <cstdio>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <csignal>
#include <fcntl.h>
#include <functional>
#include <pwd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "su.h"
#include "socket.hpp"
#include "../testRoot/super_root.h"

static struct stat self_st;
using thread_entry = void *(*)(void *);

int new_daemon_thread(thread_entry entry, void *arg) {
	pthread_t thread;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	return pthread_create(&thread, &attr, entry, arg);
}

int new_daemon_thread(void(*entry)()) {
	thread_entry proxy = [](void *entry) -> void * {
		reinterpret_cast<void(*)()>(entry)();
		return nullptr;
	};
	return new_daemon_thread(proxy, (void *)entry);
}

int new_daemon_thread(std::function<void()> &&entry) {
	thread_entry proxy = [](void *fp) -> void * {
		auto fn = reinterpret_cast<std::function<void()>*>(fp);
		(*fn)();
		delete fn;
		return nullptr;
	};
	return new_daemon_thread(proxy, new std::function<void()>(std::move(entry)));
}


void su_daemon_handler(int client, const struct ucred *credential) {
	TRACE("su: request from pid=[%d], client=[%d]\n", credential->pid, client);

	std::string shell = DEFAULT_SHELL;
	std::string command;
	int uid = 0;
	int pid = credential->pid;

	TRACE("su_daemon_handler uid:%d, pid:%d\n", uid, pid);

	// Read su request
	uid = read_int(client);
	if (uid == -1) {
		uid = UID_ROOT;
	}
	read_string(client, shell);
	read_string(client, command);

	TRACE("input shell:%s\n", shell.c_str());
	TRACE("input command:%s\n", command.c_str());


	// Fork a child root process
	//
	// The child process will need to setsid, open a pseudo-terminal
	// if needed, and eventually exec shell.
	// The parent process will wait for the result and
	// send the return code back to our client.
	int child = fork();
	if (child) {

		// Wait result
		TRACE("su: waiting child pid=[%d]\n", child);
		int status, code;

		if (waitpid(child, &status, 0) > 0)
			code = WEXITSTATUS(status);
		else
			code = -1;

		TRACE("su: return code=[%d]\n", code);
		write(client, &code, sizeof(code));
		close(client);
		return;
	}

	TRACE("su: fork handler\n");

	// ack
	write_int(client, 0);

	// Become session leader
	setsid();

	// Get pts_slave
	std::string pts_slave = read_string(client);

	// The FDs for each of the streams
	int infd = recv_fd(client);
	int outfd = recv_fd(client);
	int errfd = recv_fd(client);

	// Ã·»®
	get_root(ROOT_KEY);

	if (!pts_slave.empty()) {
		TRACE("su: pts_slave=[%s]\n", pts_slave.data());

		// Opening the TTY has to occur after the
		// fork() and setsid() so that it becomes
		// our controlling TTY and not the daemon's
		int ptsfd = open(pts_slave.data(), O_RDWR);
		if (ptsfd < 0) {
			TRACE("su: pts_slave open failed=[%s]\n", pts_slave.data());
		}
		if (infd < 0)
			infd = ptsfd;
		if (outfd < 0)
			outfd = ptsfd;
		if (errfd < 0)
			errfd = ptsfd;
	}

	// Swap out stdin, stdout, stderr
	dup2(infd, STDIN_FILENO);
	dup2(outfd, STDOUT_FILENO);
	dup2(errfd, STDERR_FILENO);

	close(infd);
	close(outfd);
	close(errfd);
	close(client);

	const char *argv[4] = { nullptr };

	argv[0] = shell.data();

	if (!command.empty()) {
		argv[1] = "-c";
		argv[2] = command.data();
	}

	// Setup environment
	umask(022);
	char path[32];
	snprintf(path, sizeof(path), "/proc/%d/cwd", pid);
	chdir(path);
	snprintf(path, sizeof(path), "/proc/%d/environ", pid);
	char buf[4096] = { 0 };
	int fd = open(path, O_RDONLY);
	read(fd, buf, sizeof(buf));
	close(fd);
	clearenv();
	for (size_t pos = 0; buf[pos];) {
		putenv(buf + pos);
		pos += strlen(buf + pos) + 1;
	}

	struct passwd *pw;
	pw = getpwuid(uid);
	if (pw) {
		setenv("HOME", pw->pw_dir, 1);
		setenv("USER", pw->pw_name, 1);
		setenv("LOGNAME", pw->pw_name, 1);
		setenv("SHELL", shell.data(), 1);
	}

	// Unblock all signals
	sigset_t block_set;
	sigemptyset(&block_set);
	sigprocmask(SIG_SETMASK, &block_set, nullptr);

	execvp(shell.data(), (char **)argv);
	fprintf(stderr, "Cannot execute %s: %s\n", shell.data(), strerror(errno));
	TRACE("exec");
	exit(EXIT_FAILURE);
}


static void handle_request(int client) {
	// Verify client credentials
	ucred cred;
	get_client_cred(client, &cred);

	// Create new thread to handle complex requests
	new_daemon_thread([=] { return su_daemon_handler(client, &cred); });
	return;

shortcut:
	close(client);
}


int su_daemon_main()
{
	// Block all signals
	sigset_t block_set;
	sigfillset(&block_set);
	pthread_sigmask(SIG_SETMASK, &block_set, nullptr);

#ifdef QUIET_PRINTF
	int fd = open("/dev/null", O_WRONLY);
	dup2(fd, STDOUT_FILENO);
	dup2(fd, STDERR_FILENO);
	if (fd > STDERR_FILENO)
		close(fd);
	fd = open("/dev/zero", O_RDONLY);
	dup2(fd, STDIN_FILENO);
	if (fd > STDERR_FILENO)
		close(fd);
#endif

	setsid();

	// Get self stat
	stat("/proc/self/exe", &self_st);

	struct sockaddr_un sun;
	socklen_t len = setup_sockaddr(&sun, DEFAULT_MAIN_SOCKET);
	int fd = socket(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (bind(fd, (struct sockaddr*) &sun, len))
	{
		TRACE("bind failed.\n");
		exit(1);
	}
	listen(fd, 10);

	// Loop forever to listen for requests
	for (;;) {
		int client = accept4(fd, nullptr, nullptr, SOCK_CLOEXEC);
		handle_request(client);
	}

	while (1) { sleep(0); }
    return 0;
}