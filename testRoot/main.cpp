#include <cstdio>
#include <sstream>
#include <sys/capability.h>

#include "super_root.h"
#include "adb_inject.h"
#define ROOT_KEY 0x7F6766F8

void show_capability_info()
{
	struct __user_cap_header_struct cap_header_data;
	cap_user_header_t cap_header = &cap_header_data;

	struct __user_cap_data_struct cap_data_data;
	cap_user_data_t cap_data = &cap_data_data;

	cap_header->pid = getpid();
	cap_header->version = _LINUX_CAPABILITY_VERSION_3; //_1、_2、_3

	if (capget(cap_header, cap_data) < 0) {
		perror("FAILED capget()");
		exit(1);
	}

	printf("Cap data 0x%x, 0x%x, 0x%x\n", cap_data->effective, cap_data->permitted, cap_data->inheritable);
	printf("now getuid()=%d,geteuid()=%d,getgid()=%d,getegid()=%d\n", getuid(), geteuid(), getgid(), getegid());

	FILE * fp = popen("getenforce", "r");
	if (fp)
	{
		char shell[512] = { 0 };
		fread(shell, 1, sizeof(shell), fp);
		pclose(fp);

		printf("SELinux status: %s\n", shell);
	}
}
void test_root()
{
	show_capability_info();

	printf("get_root ret:%d\n", get_root(ROOT_KEY));

	show_capability_info();

	//system("id");
	//system("/data/local/tmp/getmyinfo");
	//system("insmod /sdcard/rwProcMem37.ko ; echo $?");
	//system("cat /proc/1/maps");
	//system("ls /proc");
	//system("screencap -p /sdcard/temp.png");
	return;
}

void test_disable_selinux()
{
	int ret = disable_selinux(ROOT_KEY);
	printf("disable_selinux ret:%d\n", ret);
	printf("done.\n");
	return;
}

void test_enable_selinux()
{
	int ret = enable_selinux(ROOT_KEY);
	printf("enable_selinux ret:%d\n", ret);
	printf("done.\n");
	return;
}


void test_run_adb_shell(char * shell, bool bKeepAdbRoot = false) {
	printf("inject_shell_remote_process(%s)\n", shell);
	char szResult[0x1000] = { 0 };
	ssize_t ret = safe_inject_adb_process_run_shell_wrapper(ROOT_KEY, shell, bKeepAdbRoot, szResult, sizeof(szResult));
	printf("inject_shell_remote_process ret val:%zd\n", ret);
	printf("inject_shell_remote_process result:%s\n", szResult);
}

void test_run_shell(char * shell) {
	printf("test_run_shell(%s)\n", shell);
	char szResult[0x1000] = { 0 };
	ssize_t ret = safe_run_shell(ROOT_KEY, shell, szResult, sizeof(szResult));
	printf("test_run_shell ret val:%zd\n", ret);
	printf("test_run_shell result:%s\n", szResult);
}

int main(int argc, char *argv[])
{
	printf(
		"======================================================\n"
		"本工具名称: Linux ARM64 完美隐藏ROOT演示\n"
		"本工具功能列表：\n"
		"\t1.显示自身权限信息\n"
		"\t2.获取ROOT权限\n"
		"\t3.绕过SELinux\n"
		"\t4.还原SELinux\n"
		"\t5.执行ROOT Shell命令\n"
		"\t6.执行ADBShell命令\n"
		"\t7.赋予ADB最高级别权限\n"
		"\t新一代root，跟面具完全不同思路，摆脱面具被检测的弱点，完美隐藏root功能，挑战全网root检测手段，兼容安卓APP直接JNI调用，稳定、流畅、不闪退。\n"
		"======================================================\n"
	);


	++argv;
	--argc;


	if (strcmp(argv[0], "show") == 0) {
		show_capability_info();
	}
	else if (strcmp(argv[0], "root") == 0) {
		test_root();
	}
	else if (argc >=2 && strcmp(argv[0], "selinux") == 0 && strcmp(argv[1], "disable") == 0) {
		test_disable_selinux();
	}
	else if (argc >= 2 && strcmp(argv[0], "selinux") == 0 && strcmp(argv[1], "enable") == 0) {
		test_enable_selinux();
	}
	else if (argc >= 2 && strcmp(argv[0], "shell") == 0) {
		std::stringstream sstrCmd;
		for (int i = 1; i < argc; i++) {
			sstrCmd << argv[i];
		}
		test_run_shell((char*)sstrCmd.str().c_str());
	}
	else if (argc > 2 && strcmp(argv[0], "adb") == 0 && strcmp(argv[1], "shell") == 0) {
		std::stringstream sstrCmd;
		for (int i = 2; i < argc; i++) {
			sstrCmd << argv[i];
		}
		test_run_adb_shell((char*)sstrCmd.str().c_str());
	}
	else if (argc >= 2 && strcmp(argv[0], "adb") == 0 && strcmp(argv[1], "root") == 0) {
		test_run_adb_shell("id", true);
	}
	else {
		return 1;
	}

	return 0;
}