#include "env64_inject.h"
#include "ptrace_arm64_utils.h"
#include "maps_helper.h"
#include "super_root.h"
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>

#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/mman.h>

#include <sys/wait.h>

//安卓
const char *libc64_path1 = "/apex/com.android.runtime/lib64/bionic/libc.so";
const char *linker64_path1 = "/apex/com.android.runtime/bin/linker64";
//Linux
const char *libc64_path2 = "/system/lib64/libc.so";
const char *linker64_path2 = "/system/bin/linker64";



ssize_t inject_process_env64_PATH(int target_pid, const char *lpszAddPath)
{
	size_t write_len = strlen(lpszAddPath) + 1;
	size_t input_env_buf_size = getpagesize();
	ssize_t ret = -1;
	void *mmap_addr, *munmap_addr, *setresuid_addr, *getenv_addr, *putenv_addr;
	uint8_t *map_base;

	struct pt_regs regs, original_regs;
	unsigned long parameters[10];
	char zero = '\x00';
	char *default_libc64_path = (char*)libc64_path1;
	const char * str_flag_path = "PATH";
	char * ret_getenv = NULL;
	size_t tmp_read_byte_index = 0;
	char tmp_read_byte[2] = { 0 };
	char cur_path[0x1000] = { 0 };

	//将要注入的cmd命令写入前面mmap出来的内存
	if (write_len > input_env_buf_size) { //输入命令太长了
		write_len = input_env_buf_size;
	}

	TRACE("[+] Injecting process: %d\n", target_pid);

	//①ATTATCH，指定目标进程，开始调试  
	if (ptrace_attach(target_pid) == -1)
	{
		goto _ret;
	}

	//②GETREGS，获取目标进程的寄存器，保存现场  
	if (ptrace_getregs(target_pid, &regs) == -1)
	{
		goto _deatch;
	}

	/* save original registers */
	memcpy(&original_regs, &regs, sizeof(regs));

	//③通过get_remote_addr函数获取目的进程的mmap函数的地址，以便为libxxx.so分配内存  

	/*
		需要对(void*)mmap进行说明：这是取得inject本身进程的mmap函数的地址，由于mmap函数在libc.so
		库中，为了将libxxx.so加载到目的进程中，就需要使用目的进程的mmap函数，所以需要查找到libc.so库在目的进程的起始地址。
	*/
	mmap_addr = get_remote_addr(target_pid, default_libc64_path, (void *)mmap);
	if (!mmap_addr)
	{
		default_libc64_path = (char*)libc64_path2;
		TRACE("[+] choice select libc64: %s\n", default_libc64_path);
		mmap_addr = get_remote_addr(target_pid, default_libc64_path, (void *)mmap);
		if (!mmap_addr) {
			TRACE("[+] target process not found libc64: %d\n", target_pid);
			goto _deatch;
		}
	}
	munmap_addr = get_remote_addr(target_pid, default_libc64_path, (void *)munmap);
	setresuid_addr = get_remote_addr(target_pid, default_libc64_path, (void *)setresuid);
	getenv_addr = get_remote_addr(target_pid, default_libc64_path, (void *)getenv);
	putenv_addr = get_remote_addr(target_pid, default_libc64_path, (void *)putenv);
	TRACE("[+] Remote mmap address: %p\n", mmap_addr);
	TRACE("[+] Remote munmap address: %p\n", munmap_addr);
	TRACE("[+] Remote setresuid address: %p\n", setresuid_addr);
	TRACE("[+] Remote getenv address: %p\n", getenv_addr);
	TRACE("[+] Remote putenv address: %p\n", putenv_addr);

	/* call mmap (null, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC,
							 MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	匿名申请一块0x4000大小的内存
	*/
	parameters[0] = 0;  // addr      
	parameters[1] = (unsigned long)(input_env_buf_size); // size
	parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot      
	parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // flags      
	parameters[4] = 0; //fd      
	parameters[5] = 0; //offset      

	if (ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, &regs) == -1)
	{
		goto _recovery;
	}

	//⑤从寄存器中获取mmap函数的返回值，即申请的内存首地址：  
	map_base = (uint8_t *)ptrace_retval(&regs);

	//写PATH标志进mmap出来的内存
	ptrace_writedata(target_pid, map_base, (uint8_t *)str_flag_path, strlen(str_flag_path) + 1);


	parameters[0] = (unsigned long)map_base;
	//执行getenv，等于getenv("PATH");
	if (ptrace_call_wrapper(target_pid, "getenv", getenv_addr, parameters, 1, &regs) == -1)
	{
		goto _recovery;
	}
	ret_getenv = (char *)ptrace_retval(&regs);
	if (!ret_getenv) {
		//getenv error
		TRACE("getenv error\n");
		goto _recovery;
	}
	
	strcat(cur_path, "PATH=");
	do 
	{
		tmp_read_byte[0] = '\x00';
		ptrace_readdata(target_pid, (uint8_t *)((size_t)ret_getenv + tmp_read_byte_index), (uint8_t *)&tmp_read_byte, 1);
		
		tmp_read_byte_index++;
		strcat(cur_path, tmp_read_byte);

		if (tmp_read_byte_index >= sizeof(cur_path) - write_len - 1) {
			break;
		}
	} while (tmp_read_byte[0] != '\x00');
	
	strcat(cur_path, ":");
	strcat(cur_path, lpszAddPath);
	TRACE("[+] Remote cur path: %s\n", cur_path);

	//写PATH变量进mmap出来的内存
	ptrace_writedata(target_pid, map_base, (uint8_t *)cur_path, strlen(cur_path) + 1);

	//执行putenv，等于putenv("XXXXX");
	if (ptrace_call_wrapper(target_pid, "putenv", putenv_addr, parameters, 1, &regs) == -1)
	{
		goto _recovery;
	}
	if (ptrace_retval(&regs)) {
		//putenv error
		TRACE("putenv error\n");
		goto _recovery;
	}

	////解除绑定内存（不知道为什么解除内存绑定会导致对方程序crash）
	//parameters[0] = (unsigned long)map_base;// addr
	//parameters[1] = (unsigned long)(input_env_buf_size); // size

	//if (ptrace_call_wrapper(target_pid, "munmap", munmap_addr, parameters, 2, &regs) == -1)
	//{
	//	goto _recovery;
	//}

	ret = 0;
	//TRACE("Press enter to detach\n");
	//getchar();

	/* restore */
	//⑪恢复现场并退出ptrace:  
_recovery:	ptrace_setregs(target_pid, &original_regs);
_deatch:ptrace_detach(target_pid);

_ret:	return ret;
}

ssize_t inject_process_env64_PATH_wrapper(unsigned long rootKey, int target_pid, const char *lpszAddPath)
{
	if (get_root(rootKey) != 0) {
		return -1;
	}

	if (inject_process_env64_PATH(target_pid, lpszAddPath) != 0) {
		return -3;
	}
	return 0;
}


ssize_t safe_inject_process_env64_PATH_wrapper(unsigned long rootKey, int target_pid, const char *lpszAddPath)
{
	int fd[2];
	if (pipe(fd))
	{
		return -4;
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		//fork error
		return -5;

	}
	else if (pid == 0) { /* 子进程 */
		close(fd[0]); //close read pipe
		int ret = inject_process_env64_PATH_wrapper(rootKey, target_pid, lpszAddPath);
		write(fd[1], &ret, sizeof(ret));
		close(fd[1]); //close write pipe
		exit(0);
	}
	else { /*父进程*/

		close(fd[1]); //close write pipe

		int status;
		/* 等待目标进程停止或终止. WUNTRACED - 解释见参考手册 */
		if (waitpid(pid, &status, WUNTRACED) < 0) { return -6; }

		int ret = -7;
		read(fd[0], (void*)&ret, sizeof(ret));
		close(fd[0]); //close read pipe
		return ret;
	}
	return -8;
}

