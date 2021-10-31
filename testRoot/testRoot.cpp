#include "testRoot.h"
#include <sstream>
#include <thread>
#include <sys/capability.h>
#include "process64_inject.h"
#include "adb64_helper.h"
#include "su_install_helper.h"
#define ROOT_KEY 0x7F6766F8


void show_capability_info()
{
	__uid_t now_uid, now_euid, now_suid;
	if (getresuid(&now_uid, &now_euid, &now_suid)) {
		perror("FAILED getresuid()");
		return;
	}


	__gid_t now_gid, now_egid, now_sgid;
	if (getresgid(&now_gid, &now_egid, &now_sgid)) {
		perror("FAILED getresgid()");
		return;
	}

	printf("now_uid=%d, now_euid=%d, now_suid=%d, now_gid=%d, now_egid=%d, now_sgid=%d\n",
		now_uid, now_euid, now_suid,
		now_gid, now_egid, now_sgid);


	struct __user_cap_header_struct cap_header_data;
	cap_user_header_t cap_header = &cap_header_data;

	struct __user_cap_data_struct cap_data_data;
	cap_user_data_t cap_data = &cap_data_data;

	cap_header->pid = getpid();
	cap_header->version = _LINUX_CAPABILITY_VERSION_3; //_1、_2、_3

	if (capget(cap_header, cap_data) < 0) {
		perror("FAILED capget()");
		return;
	}

	printf("Cap data 0x%x, 0x%x, 0x%x\n", cap_data->effective, cap_data->permitted, cap_data->inheritable);


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

void test_run_normal_cmd(const char * shell) {
	printf("test_run_normal_cmd(%s)\n", shell);
	char result[0x1000] = { 0 };
	ssize_t ret = run_normal_cmd(ROOT_KEY, shell, result, sizeof(result));
	printf("test_run_normal_cmd ret val:%zd\n", ret);
	printf("test_run_normal_cmd result:%s\n", result);
}
void test_run_root_cmd(const char * cmd) {
	printf("test_run_root_cmd(%s)\n", cmd);
	char result[0x1000] = { 0 };
	ssize_t ret = inject_adbd64_run_cmd_wrapper(ROOT_KEY, cmd, result, sizeof(result));
	printf("test_run_root_cmd ret val:%zd\n", ret);
	printf("test_run_root_cmd result:%s\n", result);
}
void test_set_adbd_root_uid() {
	printf("test_set_adbd_root_uid\n");
	char result[0x1000] = { 0 };
	ssize_t ret = inject_adbd64_run_cmd_wrapper(ROOT_KEY, "id", result, sizeof(result), false, true, false, false);
	printf("test_set_adbd_root_uid ret val:%zd\n", ret);
}
void test_su_env_inject(const char* target_pid_cmdline)
{
	char myself_path[1024] = { 0 };
	char processname[1024];
	get_executable_path(myself_path, processname, sizeof(myself_path));
	TRACE("my directory:%s\nprocessname:%s\n", myself_path, processname);


	//1.安装su工具套件
	std::string su_hidden_path;
	int install_su_tools_ret = install_su_tools(ROOT_KEY, myself_path, su_hidden_path);
	printf("install_su_tools ret val:%d\n", install_su_tools_ret);
	if (install_su_tools_ret != 0) {
		return;
	}

	//2.杀光所有历史进程
	std::vector<pid_t> vOut;
	int find_all_cmdline_process_ret = find_all_cmdline_process(ROOT_KEY, target_pid_cmdline, vOut);
	printf("find_all_cmdline_process ret val:%d, cnt:%d\n", find_all_cmdline_process_ret, vOut.size());
	if (find_all_cmdline_process_ret != 0) {
		return;
	}
	std::string kill_cmd;
	for (pid_t t : vOut) {
		kill_cmd += "kill -9 ";
		kill_cmd += std::to_string(t);
		kill_cmd += ";";
	}
	int kill_ret = run_normal_cmd(ROOT_KEY, kill_cmd.c_str());
	printf("kill_ret ret val:%d\n", kill_ret);
	if (kill_ret != 0) {
		return;
	}

	//3.注入su环境变量到指定进程
	printf("test_auto_su_env_inject Waiting for process creation(%s)\n", target_pid_cmdline);
	int pid = wait_and_find_cmdline_process(ROOT_KEY, target_pid_cmdline);
	printf("test_auto_su_env_inject(%d)\n", pid);

	ssize_t ret = inject_process_env64_PATH_wrapper(ROOT_KEY, pid, su_hidden_path.c_str());
	printf("test_auto_su_env_inject ret val:%zd, error:%s\n", ret, strerror(errno));
}

void test_clean_su_env() {
	char myself_path[1024] = { 0 };
	char processname[1024];
	get_executable_path(myself_path, processname, sizeof(myself_path));
	TRACE("my directory:%s\nprocessname:%s\n", myself_path, processname);

	int uninstall_su_tools_ret = uninstall_su_tools(ROOT_KEY, myself_path);
	printf("test_clean_su_env ret val:%d\n", uninstall_su_tools_ret);
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
		"\t5.执行普通命令\n"
		"\t6.执行ROOT命令\n"
		"\t7.授予ADB最高级别权限\n"
		"\t8.授权ROOT到其他进程\n"
		"\t9.清理ROOT授权痕迹\n"
		"\t新一代root，跟面具完全不同思路，摆脱面具被检测的弱点，完美隐藏root功能（免root级别），兼容安卓APP直接JNI稳定调用。\n"
		"======================================================\n"
	);


	++argv;
	--argc;
	
	if (strcmp(argv[0], "show") == 0) { //1.显示自身权限信息
		show_capability_info();
	}
	else if (strcmp(argv[0], "get") == 0) { //2.获取ROOT权限
		test_root();
	}
	else if (argc >= 2 && strcmp(argv[0], "selinux") == 0 && strcmp(argv[1], "disable") == 0) {//3.绕过SELinux
		test_disable_selinux();
	}
	else if (argc >= 2 && strcmp(argv[0], "selinux") == 0 && strcmp(argv[1], "enable") == 0) { //4.还原SELinux
		test_enable_selinux();
	}
	else if (argc >= 2 && strcmp(argv[0], "shell") == 0) { //5.执行普通命令
		std::stringstream sstrCmd;
		for (int i = 1; i < argc; i++) {
			sstrCmd << argv[i];
			if (i != argc) {
				sstrCmd << " ";
			}
		}
		test_run_normal_cmd((char*)sstrCmd.str().c_str());
	}
	else if (argc >= 2 && strcmp(argv[0], "root") == 0) { //6.执行ROOT命令
		std::stringstream sstrCmd;
		for (int i = 1; i < argc; i++) {
			sstrCmd << argv[i];
			if (i != argc) {
				sstrCmd << " ";
			}
		}
		test_run_root_cmd((char*)sstrCmd.str().c_str());
	}
	else if (strcmp(argv[0], "adb") == 0) { //7.授予ADB最高级别权限
		test_set_adbd_root_uid();
	}
	else if (argc > 1 && strcmp(argv[0], "su") == 0) { //8.授权ROOT到其他进程
		std::stringstream sstrCmd;
		sstrCmd << argv[1];
		if (sstrCmd.str().length()) {
			test_su_env_inject(sstrCmd.str().c_str());
		}
	}
	else if (strcmp(argv[0], "cleansu") == 0) { //9.清理ROOT授权痕迹
		test_clean_su_env();
	}
	else {
		printf("unknown command.\n");
		return 1;
	}

	return 0;
}