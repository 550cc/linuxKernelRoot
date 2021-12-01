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

pid_t _find_adbd_pid()
{
	int id;
	pid_t pid = -1;
	DIR* dir;
	FILE *fp;
	char filename[32];
	char cmdline[256];

	struct dirent * entry;
	dir = opendir("/proc");
	if (dir == NULL)
		return -1;

	while ((entry = readdir(dir)) != NULL) {
		// 如果读取到的是"."或者".."则跳过，读取到的不是文件夹名字也跳过
		if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
			continue;
		}
		else if (entry->d_type != DT_DIR) {
			continue;
		}
		else if (strspn(entry->d_name, "1234567890") != strlen(entry->d_name)) {
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


pid_t find_adb_pid(unsigned int root_key)
{
	if (get_root(root_key) != 0) {
		return -401;
	}

	if (!is_disable_selinux_status()) {  //要关掉SELinux才能找到adb进程PID
		if (disable_selinux(root_key) != 0) {
			return -402;
		}
	}

	return _find_adbd_pid();
}

pid_t safe_find_adbd_pid(unsigned int root_key)
{
	int fd[2];
	if (pipe(fd))
	{
		return -411;
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		//fork error
		return -412;

	}
	else if (pid == 0) { /* 子进程 */
		close(fd[0]); //close read pipe
		pid_t ret = find_adb_pid(root_key);
		write(fd[1], &ret, sizeof(ret));
		close(fd[1]); //close write pipe
		force_kill_myself();
	}
	else { /*父进程*/

		close(fd[1]); //close write pipe

		int status;
		/* 等待目标进程停止或终止. WUNTRACED - 解释见参考手册 */
		if (waitpid(pid, &status,  WUNTRACED) < 0 && errno != EACCES) { return -6; }

		pid_t ret = -413;
		read(fd[0], (void*)&ret, sizeof(ret));
		
		close(fd[0]); //close read pipe
		return ret;
	}
	return -414;
}

int kill_adbd_process(unsigned int root_key) {
	pid_t adb_pid = find_adb_pid(root_key);
	if (adb_pid < 0) {
		TRACE("Could not found the ADB daemon process.Please open ADB.\n");
		return -420;
	}
	char kill_shell[256] = { 0 };
	snprintf(kill_shell, sizeof(kill_shell), "kill -9 %d", adb_pid);
	return run_normal_cmd(root_key, kill_shell);
}
int safe_kill_adbd_process(unsigned int root_key) {

	int fd[2];
	if (pipe(fd))
	{
		return -421;
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		//fork error
		return -422;

	}
	else if (pid == 0) { /* 子进程 */
		close(fd[0]); //close read pipe
		pid_t ret = kill_adbd_process(root_key);
		write(fd[1], &ret, sizeof(ret));
		close(fd[1]); //close write pipe
		force_kill_myself();
	}
	else { /*父进程*/

		close(fd[1]); //close write pipe

		int status;
		/* 等待目标进程停止或终止. WUNTRACED - 解释见参考手册 */
		if (waitpid(pid, &status,  WUNTRACED) < 0 && errno != EACCES) { return -6; }

		pid_t ret = -423;
		read(fd[0], (void*)&ret, sizeof(ret));
		
		close(fd[0]); //close read pipe
		return ret;
	}
	return -424;
}

int kill_process(unsigned int root_key, pid_t pid) {
	char kill_shell[256] = { 0 };
	snprintf(kill_shell, sizeof(kill_shell), "kill -9 %d", pid);
	return run_normal_cmd(root_key, kill_shell);
}
int safe_kill_process(unsigned int root_key, pid_t pid) {
	char kill_shell[256] = { 0 };
	snprintf(kill_shell, sizeof(kill_shell), "kill -9 %d", pid);
	return safe_run_normal_cmd(root_key, kill_shell);
}


//注入adb64进程远程执行命令，备注：此命令会自动提权到ROOT、并且关闭SELinux。结束运行后可根据自己的需要决定是否手动重新打开SELinux
ssize_t inject_adbd64_run_cmd_wrapper(unsigned int root_key,
	const char *cmd,
	const char* p_out_result_buf/* = NULL*/,
	size_t out_result_buf_size/* = 0*/,
	bool afert_kill_adb/* = true*/,
	bool user_root_auth/* = true*/,
	bool after_recovery_last_uid/* = true*/,
	bool after_recovery_last_gid/* = true*/,
	const char * chdir_path/* = NULL*/,
	bool clear_env/* = false*/,
	std::vector<process64_env> *set_env/* = NULL*/) {
	pid_t adb_pid = find_adb_pid(root_key);
	if (adb_pid < 0) {
		TRACE("Could not found the ADB daemon process.Please open ADB.\n");
		return -430;
	}
	ssize_t ret = inject_process64_run_cmd_wrapper(root_key, adb_pid, cmd, p_out_result_buf, out_result_buf_size, user_root_auth, after_recovery_last_uid, after_recovery_last_gid, chdir_path, clear_env, set_env);

	if (afert_kill_adb) {
		kill_process(root_key, adb_pid);
	}
	return ret;
}
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_inject_adbd64_run_cmd_wrapper(unsigned int root_key,
	const char *cmd,
	const char* p_out_result_buf/* = NULL*/,
	size_t out_result_buf_size/* = 0*/,
	bool afert_kill_adb/* = true*/,
	bool user_root_auth/* = true*/,
	bool after_recovery_last_uid/* = true*/,
	bool after_recovery_last_gid/* = true*/,
	const char * chdir_path/* = NULL*/,
	bool clear_env/* = false*/,
	std::vector<process64_env> *set_env/* = NULL*/) {
	pid_t adb_pid = safe_find_adbd_pid(root_key);
	if (adb_pid < 0) {
		TRACE("Could not found the ADB daemon process.Please open ADB.\n");
		return -431;
	}
	ssize_t ret = safe_inject_process64_run_cmd_wrapper(root_key, adb_pid, cmd, p_out_result_buf, out_result_buf_size, user_root_auth, after_recovery_last_uid, after_recovery_last_gid, chdir_path, clear_env, set_env);

	if (afert_kill_adb) {
		safe_kill_process(root_key, adb_pid);
	}
	return ret;
}
