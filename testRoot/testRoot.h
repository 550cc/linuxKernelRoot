#ifndef TEST_ROOT_H_
#define TEST_ROOT_H_
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <vector>
#include "kernel_root_helper.h"

//安静输出模式
#define QUIET_PRINTF

#ifdef QUIET_PRINTF
#undef TRACE
#define TRACE(fmt, ...)
#else
#ifdef __ANDROID__
#include <android/log.h>
#define LOG_TAG "JNIGlue"
//#define TRACE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define TRACE(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define TRACE(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif
#endif


static size_t get_executable_path(char* processdir, char* processname, size_t len)
{
	char* path_end;
	if (readlink("/proc/self/exe", processdir, len) <= 0)
	{
		return -1;
	}
	path_end = strrchr(processdir, '/');
	if (path_end == NULL)
	{
		return -1;
	}
	++path_end;
	strcpy(processname, path_end);
	*path_end = '\0';
	return (size_t)(path_end - processdir);
}
static int find_all_cmdline_process(unsigned int root_key, const char* target_cmdline, std::vector<pid_t> & vOut)
{
	int id;
	DIR* dir;
	FILE *fp;
	char filename[32];
	char cmdline[256];

	struct dirent * entry;

	if (get_root(root_key) != 0) {
		return -1;
	}

	if (!is_disable_selinux_status()) {  //要关掉SELinux才能找到进程PID
		if (disable_selinux(root_key) != 0) {
			return -2;
		}
	}

	dir = opendir("/proc");
	if (dir == NULL)
		return -3;

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
				if (strstr(cmdline, target_cmdline)) {
					/* process found */
					vOut.push_back(id);
				}
			}
		}
	}

	closedir(dir);
	return 0;
}

static int safe_find_all_cmdline_process(unsigned int root_key, const char* target_cmdline, std::vector<pid_t> & vOut)
{
	int fd[2];
	if (pipe(fd)) {
		return -1000;
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		//fork error
		return -1001;

	}
	else if (pid == 0) { /* 子进程 */
		close(fd[0]); //close read pipe
		int ret = find_all_cmdline_process(root_key, target_cmdline, vOut);
		write(fd[1], &ret, sizeof(ret));
		size_t cnt = vOut.size();
		write(fd[1], &cnt, sizeof(cnt));
		for (pid_t t : vOut) {
			write(fd[1], &t, sizeof(t));
		}
		close(fd[1]); //close write pipe
		exit(0);
	}
	else { /*父进程*/

		close(fd[1]); //close write pipe

		int status;
		/* 等待目标进程停止或终止. WUNTRACED - 解释见参考手册 */
		if (waitpid(pid, &status, WNOHANG | WUNTRACED) < 0) { return -6; }

		int ret = -1002;
		read(fd[0], (void*)&ret, sizeof(ret));
		size_t cnt = 0;
		read(fd[0], (void*)&cnt, sizeof(cnt));
		for (size_t i = 0; i < cnt; i++) {
			pid_t t;
			read(fd[0], (void*)&t, sizeof(t));
			vOut.push_back(t);
		}

		close(fd[0]); //close read pipe
		return ret;
	}
	return -1003;
}


static int wait_and_find_cmdline_process(unsigned int root_key, const char* target_cmdline)
{
	int id;
	pid_t pid = -1;
	DIR* dir;
	FILE *fp;
	char filename[32];
	char cmdline[256];

	struct dirent * entry;

	if (get_root(root_key) != 0) {
		return -1;
	}

	if (!is_disable_selinux_status()) {  //要关掉SELinux才能找到进程PID
		if (disable_selinux(root_key) != 0) {
			return -2;
		}
	}

	while (1) {
		sleep(0);

		dir = opendir("/proc");
		if (dir == NULL)
			return -3;

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
					if (strstr(cmdline, target_cmdline)) {
						/* process found */
						pid = id;
						break;
					}
				}
			}
		}

		closedir(dir);
		if (pid <= 0) {
			continue;
		}
		break;
	}
	return pid;
}

static int safe_wait_and_find_cmdline_process(unsigned int root_key, const char* target_cmdline)
{
	int fd[2];
	if (pipe(fd)) {
		return -1000;
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		//fork error
		return -1001;

	}
	else if (pid == 0) { /* 子进程 */
		close(fd[0]); //close read pipe
		int ret = wait_and_find_cmdline_process(root_key, target_cmdline);
		write(fd[1], &ret, sizeof(ret));
		close(fd[1]); //close write pipe
		exit(0);
	}
	else { /*父进程*/

		close(fd[1]); //close write pipe

		int status;
		/* 等待目标进程停止或终止. WUNTRACED - 解释见参考手册 */
		if (waitpid(pid, &status, WNOHANG | WUNTRACED) < 0) { return -6; }

		int ret = -1002;
		read(fd[0], (void*)&ret, sizeof(ret));
		close(fd[0]); //close read pipe
		return ret;
	}
	return -1003;
}


#endif /* TEST_ROOT_H_ */
