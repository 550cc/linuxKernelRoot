#ifndef _PROCESS64_INJECT_H_
#define _PROCESS64_INJECT_H_
#include "testRoot.h"
#include <unistd.h>
#include <vector>


//注入64位进程远程执行命令，备注：此命令会自动提权到ROOT、并且关闭SELinux。结束运行后可根据自己的需要决定是否手动重新打开SELinux
struct process64_env {
	char key[0x1000]; //key和name的值不能大于pagesize
	char value[0x1000];
};
ssize_t inject_process64_run_cmd_wrapper(
	const char* str_root_key,
	pid_t target_pid,
	const char *cmd,
	const char* p_out_result_buf = NULL,
	size_t out_result_buf_size = 0,
	bool user_root_auth = true,
	bool after_recovery_last_uid = false,
	bool after_recovery_last_gid = false,
	const char * chdir_path = NULL,
	bool clear_env = false,
	std::vector<process64_env> *set_env = NULL);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_inject_process64_run_cmd_wrapper(
	const char* str_root_key,
	pid_t target_pid,
	const char *cmd,
	const char* p_out_result_buf = NULL,
	size_t out_result_buf_size = 0,
	bool user_root_auth = true,
	bool after_recovery_last_uid = false,
	bool after_recovery_last_gid = false,
	const char * chdir_path = NULL,
	bool clear_env = false,
	std::vector<process64_env> *set_env = NULL);

//注入远程进程添加PATH变量路径，备注：此命令会自动提权到ROOT、并且关闭SELinux。结束运行后可根据自己的需要决定是否手动重新打开SELinux
ssize_t inject_process_env64_PATH_wrapper(const char* str_root_key, int target_pid, const char *add_path);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_inject_process_env64_PATH_wrapper(const char* str_root_key, int target_pid, const char *add_path);

//注入64位进程动态链接库so，备注：此命令会自动提权到ROOT、并且关闭SELinux。结束运行后可根据自己的需要决定是否手动重新打开SELinux
ssize_t inject_process64_so_wrapper(const char* str_root_key, pid_t target_pid, const char *p_target_so_path, const char* p_target_so_func_name);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_inject_process64_so_wrapper(const char* str_root_key, pid_t target_pid, const char *p_target_so_path, const char* p_target_so_func_name);


int kill_process(const char* str_root_key, pid_t pid = true);
int safe_kill_process(const char* str_root_key, pid_t pid = true);

int kill_process_ex(const char* str_root_key, const std::vector<pid_t> & vpid);
int safe_kill_process_ex(const char* str_root_key, const std::vector<pid_t> & vpid);
#endif /* _PROCESS64_INJECT_H_ */
