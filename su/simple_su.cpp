#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <pwd.h>
#include <sys/wait.h>

#include "su.h"
#include "../testRoot/testRoot.h"
#include "../testRoot/kernel_root_helper.h"
#include "root_key_helper.h"

#define ROOT_KEY 0x7F6766F8

//   su -->  argv[0]    argv[1] == NULL
//   su -->  argv[0]    argv[1] == "stu"
int main(int argc, char *argv[])
{
	char myself_path[1024] = { 0 };
	char processname[1024];
	get_executable_path(myself_path, processname, sizeof(myself_path));
	TRACE("my directory:%s\nprocessname:%s\n", myself_path, processname);
	unsigned int root_key = get_tmp_root_key(myself_path);
	if (root_key == 0) {
		TRACE("root_key empty\n");
		return EXIT_FAILURE;
	}
	//保存旧的SELinux状态
	bool old_selinux_disable = is_disable_selinux_status();

	const char *user = "root";
	if (argv[1] != NULL) {
		user = argv[1];
	}

	pid_t n = fork();
	assert(-1 != n);
	if (0 == n) {
		struct passwd *pw = getpwnam(user);  //  passwd结构体指针指向的是新用户的信息
		assert(pw != NULL);

		//setuid(pw->pw_uid);  // 切换到新用户

		//提权
	
		if (get_root(root_key) != 0) {
			TRACE("get_root failed\n");
			return EXIT_FAILURE;
		}

		if (!is_disable_selinux_status()) {  //要关掉SELinux才能找到adb进程PID
			if (disable_selinux(root_key) != 0) {
				TRACE("disable selinux failed\n");
				return EXIT_FAILURE;
			}
		}



		get_root(ROOT_KEY);

		setenv("HOME", pw->pw_dir, 1);  //   在程序中修改环境变量

		execl(pw->pw_shell, pw->pw_shell, (char*)0);  //  main函数的参数至少有一个（执行进程的命令）
		perror("execl error: ");
	}
	else {
		wait(NULL);  //  等创建的子进程(新启动bash)退出
		
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
	exit(0);
}
