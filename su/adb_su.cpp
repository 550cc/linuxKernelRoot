#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <dirent.h>
#include <iostream>
#include <memory>

#include <sys/types.h>
#include <sys/stat.h>

#include "su.h"
#include "root_key_helper.h"
#include "../testRoot/kernel_root_helper.h"
#include "../testRoot/adb64_helper.h"

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

	setup_sighandlers(sighandler);

	// Setup environment
	umask(022);
	char chdir_path[32];
	snprintf(chdir_path, sizeof(chdir_path), "/proc/%d/cwd", getpid());
	//chdir(chdir_path); //在下面将会以我的方式重写它

	char path[32];
	snprintf(path, sizeof(path), "/proc/%d/environ", getpid());
	char buf[4096] = { 0 };
	int fd = open(path, O_RDONLY);
	read(fd, buf, sizeof(buf));
	close(fd);

	//clearenv(); //在下面将会以我的方式重写它

	std::vector<process64_env> v_process64_env;
	for (size_t pos = 0; buf[pos];) {
		char head[0x1000] = { 0 };
		char val[0x1000] = { 0 };
		char * find = strrchr(buf + pos, '=');
		if (!find) {
			TRACE("unknow env:%s\n", buf + pos);
			continue;
		}
		auto head_size = find - (buf + pos);
		if (head_size > sizeof(head) - 1) {
			TRACE("env head size too large:%s\n", buf + pos);
			continue;
		}
		memcpy(head, buf + pos, head_size);
		find++;

		auto val_size = strlen(find);
		if (val_size > sizeof(head) - 1) {
			TRACE("env val size too large:%s\n", buf + pos);
			continue;
		}
		memcpy(val, find, val_size);

		TRACE("new env head:%s\n", head);
		TRACE("new env val:%s\n", val);

		process64_env new_env;
		strcpy(new_env.key, head);
		strcpy(new_env.value, val);
		v_process64_env.push_back(new_env);
		//putenv(buf + pos); //在下面将会以我的方式重写它
		pos += strlen(buf + pos) + 1;
	}

	struct passwd *pw;
	pw = getpwuid(uid);
	if (pw) {
		process64_env new_env_HOME;
		strcpy(new_env_HOME.key, "HOME");
		strcpy(new_env_HOME.value, pw->pw_dir);
		v_process64_env.push_back(new_env_HOME);


		process64_env new_env_USER;
		strcpy(new_env_USER.key, "USER");
		strcpy(new_env_USER.value, pw->pw_name);
		v_process64_env.push_back(new_env_USER);



		process64_env new_env_LOGNAME;
		strcpy(new_env_LOGNAME.key, "LOGNAME");
		strcpy(new_env_LOGNAME.value, pw->pw_name);
		v_process64_env.push_back(new_env_LOGNAME);



		process64_env new_env_SHELL;
		strcpy(new_env_SHELL.key, "SHELL");
		strcpy(new_env_SHELL.value, shell.data());
		v_process64_env.push_back(new_env_SHELL);
	}

	//提权
	char myself_path[1024] = { 0 };
	char processname[1024];
	get_executable_path(myself_path, processname, sizeof(myself_path));
	TRACE("my directory:%s\nprocessname:%s\n", myself_path, processname);
	unsigned int root_key = get_tmp_root_key(myself_path);
	if (root_key == 0) {
		TRACE("root_key empty\n");
		return EXIT_FAILURE;
	}

	//TODO：命令解析简陋版，暂时不支持EXPORT、多行等命令
	while (1)
	{
		
		//获取用户输入的命令
		printf("root# ");

		std::string input_command;
		getline(std::cin, input_command);
		TRACE("[+] su new len: %zu, input_command: %s\n", input_command.length(), input_command.c_str());
		if (input_command.empty()) {
			continue;
		}
		else if (input_command == "exit") {
			break;
		}
		else if (input_command == "setenforce 0") {
			int err = safe_disable_selinux(root_key);
			if (err) {
				std::cout << "safe_disable_selinux ret:" << err << std::endl;
			}
			continue;
		}
		else if (input_command == "setenforce 1") {
			int err = safe_enable_selinux(root_key);
			if (err) {
				std::cout << "safe_enable_selinux ret:" << err << std::endl;
			}
			continue;
		}

		//保存旧的SELinux状态
		bool old_selinux_disable = is_disable_selinux_status();

		//执行命令
		char out_buf[0x1000] = { 0 }; //TODO：暂时用一页内存装，后面再改进
		ssize_t inject_ret = safe_inject_adbd64_run_cmd_wrapper(root_key, input_command.c_str(), out_buf, sizeof(out_buf), false, true, true, true, chdir_path, true, &v_process64_env);
		if (inject_ret < 0) {
			std::cout << "inject_adbd64_run_cmd_wrapper ret:"<< inject_ret << std::endl;
			return EXIT_FAILURE;
		}
		std::cout << out_buf;

		
		//恢复SELinux状态
		if (is_disable_selinux_status() != old_selinux_disable) {
			if (old_selinux_disable) {
				safe_disable_selinux(root_key);
			}
			else {
				safe_enable_selinux(root_key);
			}

		}
	}
	TRACE("exit code: EXIT_SUCCESS\n");
	return EXIT_SUCCESS;
}



int main(int argc, char *argv[])
{
	pid_t n = fork();
	if (0 == n) {
		su_client_main(argc, argv);
		exit(0);
	}
	else {
		wait(NULL);
	}
	return 0;
}
