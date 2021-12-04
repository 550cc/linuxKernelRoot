#ifndef INIT64_HELPER_H_
#define INIT64_HELPER_H_
#include <unistd.h>
#include "process64_inject.h"

//注入init64进程远程执行命令，备注：此命令会自动提权到ROOT、并且关闭SELinux。结束运行后可根据自己的需要决定是否手动重新打开SELinux
ssize_t inject_init64_run_cmd_wrapper(
	unsigned int root_key,
	const char *cmd,
	const char* p_out_result_buf = NULL,
	size_t out_result_buf_size = 0) {
	return inject_process64_run_cmd_wrapper(root_key, 1, cmd, p_out_result_buf, out_result_buf_size, false, false, false, NULL, false, NULL);
}

//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_inject_init64_run_cmd_wrapper(
	unsigned int root_key,
	const char *cmd,
	const char* p_out_result_buf = NULL,
	size_t out_result_buf_size = 0) {
	return safe_inject_process64_run_cmd_wrapper(root_key, 1, cmd, p_out_result_buf, out_result_buf_size, false, false, false, NULL, false, NULL);
}
#endif /* INIT64_HELPER_H_ */
