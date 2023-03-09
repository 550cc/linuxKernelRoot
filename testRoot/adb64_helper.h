#ifndef ADB64_HELPER_H_
#define ADB64_HELPER_H_
#include <unistd.h>
#include "process64_inject.h"

//注入adbd64进程远程执行命令，备注：此命令会自动提权到ROOT、并且关闭SELinux。结束运行后可根据自己的需要决定是否手动重新打开SELinux
ssize_t inject_adbd64_run_cmd_wrapper(
	const char* str_root_key,
	const char *cmd,
	const char* p_out_result_buf = NULL,
	size_t out_result_buf_size = 0,
	bool after_kill_adb = true,
	bool user_root_auth = true,
	bool after_recovery_last_uid = true,
	bool after_recovery_last_gid = true,
	const char * chdir_path = NULL,
	bool clear_env = false,
	std::vector<process64_env> *set_env = NULL);

//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_inject_adbd64_run_cmd_wrapper(
	const char* str_root_key,
	const char *cmd,
	const char* p_out_result_buf = NULL,
	size_t out_result_buf_size = 0,
	bool after_kill_adb = true,
	bool user_root_auth = true,
	bool after_recovery_last_uid = true,
	bool after_recovery_last_gid = true,
	const char * chdir_path = NULL,
	bool clear_env = false,
	std::vector<process64_env> *set_env = NULL);

int kill_adbd_process(const char* str_root_key);
int safe_kill_adbd_process(const char* str_root_key);
#endif /* ADB64_HELPER_H_ */
