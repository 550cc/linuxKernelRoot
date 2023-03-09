#include "adb64_helper.h"
#include "kernel_root_helper.h"
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <iostream>
#include <sstream>
#include <thread>
#include <atomic>

#define ADB_TCP_PORT_MIN 50000
#define ADB_TCP_PORT_MAX 60000

pid_t _find_adbd_pid() {
	int id;
	pid_t pid = -1;
	DIR* dir;
	FILE* fp;
	char filename[32];
	char cmdline[256];

	struct dirent* entry;
	dir = opendir("/proc");
	if (dir == NULL)
		return -1;

	while ((entry = readdir(dir)) != NULL) {
		// 如果读取到的是"."或者".."则跳过，读取到的不是文件夹名字也跳过
		if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
			continue;
		} else if (entry->d_type != DT_DIR) {
			continue;
		} else if (strspn(entry->d_name, "1234567890") != strlen(entry->d_name)) {
			continue;
		}

		id = atoi(entry->d_name);
		if (id != 0) {
			sprintf(filename, "/proc/%d/cmdline", id);
			fp = fopen(filename, "r");
			if (fp) {
				fgets(cmdline, sizeof(cmdline), fp);
				fclose(fp);
				//TRACE("[+] find %d process cmdline: %s\n", id, cmdline);
				if ((strcmp("/system/bin/adbd", cmdline) == 0)
					|| (strstr(cmdline, "/bin/adbd"))) {
					/* process found */
					pid = id;
					break;
				}
			}
		}
	}

	closedir(dir);
	return pid;
}


pid_t find_adb_pid(const char* str_root_key) {
	if (kernel_root::get_root(str_root_key) != 0) {
		return -401;
	}
	int pid = _find_adbd_pid();
	return pid;
}

pid_t safe_find_adbd_pid(const char* str_root_key) {
	int fd[2];
	if (pipe(fd)) {
		return -411;
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		//fork error
		return -412;
	} else if (pid == 0) { // child process
		close(fd[0]); //close read pipe
		pid_t ret = find_adb_pid(str_root_key);
		write(fd[1], &ret, sizeof(ret));
		close(fd[1]); //close write pipe
		_exit(0);
	} else { // father process
		close(fd[1]); //close write pipe
		int status;
		if (waitpid(pid, &status, WUNTRACED) < 0 && errno != EACCES) {
			return -413;
		}
		pid_t ret = -414;
		read(fd[0], (void*)&ret, sizeof(ret));
		close(fd[0]); //close read pipe
		return ret;
	}
	return -415;
}

int kill_adbd_process(const char* str_root_key) {
	pid_t adb_pid = find_adb_pid(str_root_key);
	if (adb_pid < 0) {
		TRACE("Could not found the ADB daemon process.Please open ADB.\n");
		return -420;
	}
	return kill_process(str_root_key, adb_pid);
}

int safe_kill_adbd_process(const char* str_root_key) {

	int fd[2];
	if (pipe(fd)) {
		return -422;
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		//fork error
		return -423;

	} else if (pid == 0) { // child process
		close(fd[0]); //close read pipe
		pid_t ret = kill_adbd_process(str_root_key);
		write(fd[1], &ret, sizeof(ret));
		close(fd[1]); //close write pipe
		_exit(0);
	} else { // father process

		close(fd[1]); //close write pipe

		int status;

		if (waitpid(pid, &status, WUNTRACED) < 0 && errno != EACCES) {
			return -424;
		}

		pid_t ret = -425;
		read(fd[0], (void*)&ret, sizeof(ret));
		close(fd[0]); //close read pipe

		//恢复SELinux
		return ret;

	}
	return -426;
}


//注入adb64进程远程执行命令，备注：此命令会自动提权到ROOT、并且关闭SELinux。结束运行后可根据自己的需要决定是否手动重新打开SELinux
ssize_t inject_adbd64_run_cmd_wrapper(const char* str_root_key,
	const char* cmd,
	const char* p_out_result_buf/* = NULL*/,
	size_t out_result_buf_size/* = 0*/,
	bool after_kill_adb/* = true*/,
	bool user_root_auth/* = true*/,
	bool after_recovery_last_uid/* = true*/,
	bool after_recovery_last_gid/* = true*/,
	const char* chdir_path/* = NULL*/,
	bool clear_env/* = false*/,
	std::vector<process64_env>* set_env/* = NULL*/) {
	pid_t adb_pid = find_adb_pid(str_root_key);
	if (adb_pid < 0) {
		TRACE("Could not found the ADB daemon process.Please open ADB.\n");
		return -430;
	}
	ssize_t ret = inject_process64_run_cmd_wrapper(str_root_key, adb_pid, cmd, p_out_result_buf, out_result_buf_size, user_root_auth, after_recovery_last_uid, after_recovery_last_gid, chdir_path, clear_env, set_env);

	if (after_kill_adb) {
		kill_process(str_root_key, adb_pid);
	}
	return ret;
}
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_inject_adbd64_run_cmd_wrapper(const char* str_root_key,
	const char* cmd,
	const char* p_out_result_buf/* = NULL*/,
	size_t out_result_buf_size/* = 0*/,
	bool after_kill_adb/* = true*/,
	bool user_root_auth/* = true*/,
	bool after_recovery_last_uid/* = true*/,
	bool after_recovery_last_gid/* = true*/,
	const char* chdir_path/* = NULL*/,
	bool clear_env/* = false*/,
	std::vector<process64_env>* set_env/* = NULL*/) {
	pid_t adb_pid = safe_find_adbd_pid(str_root_key);
	if (adb_pid < 0) {
		TRACE("Could not found the ADB daemon process.Please open ADB.\n");
		return -431;
	}
	ssize_t ret = safe_inject_process64_run_cmd_wrapper(str_root_key, adb_pid, cmd, p_out_result_buf, out_result_buf_size, user_root_auth, after_recovery_last_uid, after_recovery_last_gid, chdir_path, clear_env, set_env);

	if (after_kill_adb) {
		safe_kill_process(str_root_key, adb_pid);
	}
	return ret;
}
