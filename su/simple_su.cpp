#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <pwd.h>
#include <sys/wait.h>

#include "su.h"
#include "../testRoot/super_root.h"



//   su -->  argv[0]    argv[1] == NULL
//   su -->  argv[0]    argv[1] == "stu"
int main(int argc, char *argv[])
{
	const char *user = "root";
	if (argv[1] != NULL)
	{
		user = argv[1];
	}

	pid_t n = fork();
	assert(-1 != n);
	if (0 == n)
	{
		struct passwd *pw = getpwnam(user);  //  passwd结构体指针指向的是新用户的信息
		assert(pw != NULL);

		//setuid(pw->pw_uid);  // 切换到新用户
		get_root(ROOT_KEY);

		setenv("HOME", pw->pw_dir, 1);  //   在程序中修改环境变量

		execl(pw->pw_shell, pw->pw_shell, (char*)0);  //  main函数的参数至少有一个（执行进程的命令）
		perror("execl error: ");
	}
	else
	{
		wait(NULL);  //  等创建的子进程(新启动bash)退出
	}

	exit(0);
}
