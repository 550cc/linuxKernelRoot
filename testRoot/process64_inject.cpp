#include "process64_inject.h"
#include "ptrace_arm64_utils.h"
#include "maps_helper.h"
#include "kernel_root_helper.h"
#include "so_symbol_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <dlfcn.h>

#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <map>

int safe_load_libc64_run_cmd_func_addr(
	unsigned int root_key,
	const char* so_path,
	size_t & p_mmap_offset,
	size_t & p_munmap_offset,
	size_t & p_chdir_offset,
	size_t & p_clearenv_offset,
	size_t & p_setenv_offset,
	size_t & p_getuid_offset,
	size_t & p_setuid_offset,
	size_t & p_getgid_offset,
	size_t & p_setgid_offset,

/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/


	size_t & p_system_offset,
	size_t & p_pipe_offset,
	size_t & p_dup_offset,
	size_t & p_dup2_offset,
	size_t & p_read_offset,
	size_t & p_fcntl_offset,
	size_t & p_close_offset) {


	void * p_so_addr = get_module_base(-1, so_path);
	if (p_so_addr) {
		TRACE("myself have this so.\n");
		//自身有这个so
		void * p_so = dlopen(so_path, RTLD_NOW | RTLD_GLOBAL);
		if (p_so) {
			void * p_mmap = dlsym(p_so, "mmap");
			void * p_munmap = dlsym(p_so, "munmap");
			void * p_chdir = dlsym(p_so, "chdir");
			void * p_clearenv = dlsym(p_so, "clearenv");
			void * p_setenv = dlsym(p_so, "setenv");
			void * p_getuid = dlsym(p_so, "getuid");
			void * p_setuid = dlsym(p_so, "setuid");
			void * p_getgid = dlsym(p_so, "getgid");
			void * p_setgid = dlsym(p_so, "setgid");
/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/
			void * p_system = dlsym(p_so, "system");
			void * p_pipe = dlsym(p_so, "pipe");
			void * p_dup = dlsym(p_so, "dup");
			void * p_dup2 = dlsym(p_so, "dup2");
			void * p_read = dlsym(p_so, "read");
			void * p_fcntl = dlsym(p_so, "fcntl");
			void * p_close = dlsym(p_so, "close");
			dlclose(p_so);
			p_chdir_offset = p_chdir ? ((size_t)p_chdir - (size_t)p_so_addr) : 0;
			p_clearenv_offset = p_clearenv ? ((size_t)p_clearenv - (size_t)p_so_addr) : 0;
			p_setenv_offset = p_setenv ? ((size_t)p_setenv - (size_t)p_so_addr) : 0;
			p_setuid_offset = p_setuid ? ((size_t)p_setuid - (size_t)p_so_addr) : 0;
			p_getgid_offset = p_getgid ? ((size_t)p_getgid - (size_t)p_so_addr) : 0;
			p_setgid_offset = p_setgid ? ((size_t)p_setgid - (size_t)p_so_addr) : 0;
			if (p_mmap && p_munmap && p_getuid /*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/ && p_system && p_pipe && p_dup && p_dup2 && p_read && p_fcntl && p_close) {
				p_mmap_offset = ((size_t)p_mmap - (size_t)p_so_addr);
				p_munmap_offset = ((size_t)p_munmap - (size_t)p_so_addr);
				p_getuid_offset = ((size_t)p_getuid - (size_t)p_so_addr);
				/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/
				p_system_offset = ((size_t)p_system - (size_t)p_so_addr);
				p_pipe_offset = ((size_t)p_pipe - (size_t)p_so_addr);
				p_dup_offset = ((size_t)p_dup - (size_t)p_so_addr);
				p_dup2_offset = ((size_t)p_dup2 - (size_t)p_so_addr);
				p_read_offset = ((size_t)p_read - (size_t)p_so_addr);
				p_fcntl_offset = ((size_t)p_fcntl - (size_t)p_so_addr);
				p_close_offset = ((size_t)p_close - (size_t)p_so_addr);
				return 0;

			}
		}
	}
	//自身没这个so

	std::map<std::string, uint64_t> funcSymbolMap;
	funcSymbolMap["mmap"] = 0;
	funcSymbolMap["munmap"] = 0;
	funcSymbolMap["chdir"] = 0;
	funcSymbolMap["clearenv"] = 0;
	funcSymbolMap["setenv"] = 0;
	funcSymbolMap["getuid"] = 0;
	funcSymbolMap["setuid"] = 0;
	funcSymbolMap["getgid"] = 0;
	funcSymbolMap["setgid"] = 0;
/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/
	funcSymbolMap["system"] = 0;
	funcSymbolMap["pipe"] = 0;
	funcSymbolMap["dup"] = 0;
	funcSymbolMap["dup2"] = 0;
	funcSymbolMap["read"] = 0;
	funcSymbolMap["fcntl"] = 0;
	funcSymbolMap["close"] = 0;
	int ret = get_so_symbol_addr(so_path, funcSymbolMap);
	p_mmap_offset = funcSymbolMap["mmap"];
	p_munmap_offset = funcSymbolMap["munmap"];
	p_chdir_offset = funcSymbolMap["chdir"];
	p_clearenv_offset = funcSymbolMap["clearenv"];
	p_setenv_offset = funcSymbolMap["setenv"];
	p_setuid_offset = funcSymbolMap["setuid"];
	p_getuid_offset = funcSymbolMap["getuid"];
	p_setgid_offset = funcSymbolMap["setgid"];
	p_getgid_offset = funcSymbolMap["getgid"];
/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/
	p_system_offset = funcSymbolMap["system"];
	p_pipe_offset = funcSymbolMap["pipe"];
	p_dup_offset = funcSymbolMap["dup"];
	p_dup2_offset = funcSymbolMap["dup2"];
	p_read_offset = funcSymbolMap["read"];
	p_fcntl_offset = funcSymbolMap["fcntl"];
	p_close_offset = funcSymbolMap["close"];
	return ret;
}

int safe_load_libc64_so_inject_func_addr(
	unsigned int root_key,
	const char* so_path,
	size_t & p_dlopen_offset,
	size_t & p_dlsym_offset,
	size_t & p_mmap_offset,
	size_t & p_munmap_offset) {


	void * p_so_addr = get_module_base(-1, so_path);
	if (p_so_addr) {
		//自身有这个so
		void * p_so = dlopen(so_path, RTLD_NOW | RTLD_GLOBAL);
		if (p_so) {
			void * p_dlopen = dlsym(p_so, "dlopen");
			void * p_dlsym = dlsym(p_so, "dlsym");
			void * p_mmap = dlsym(p_so, "mmap");
			void * p_munmap = dlsym(p_so, "munmap");
			dlclose(p_so);
			if (p_dlopen && p_dlsym && p_mmap && p_munmap) {
				p_dlopen_offset = ((size_t)p_dlopen - (size_t)p_so_addr);
				p_dlsym_offset = ((size_t)p_dlsym - (size_t)p_so_addr);
				p_mmap_offset = ((size_t)p_mmap - (size_t)p_so_addr);
				p_munmap_offset = ((size_t)p_munmap - (size_t)p_so_addr);
				return 0;

			}
		}
	}

	std::map<std::string, uint64_t> funcSymbolMap;
	funcSymbolMap["dlopen"] = 0;
	funcSymbolMap["dlsym"] = 0;
	funcSymbolMap["mmap"] = 0;
	funcSymbolMap["munmap"] = 0;
	int ret = get_so_symbol_addr(so_path, funcSymbolMap);
	p_dlopen_offset = funcSymbolMap["dlopen"];
	p_dlsym_offset = funcSymbolMap["dlsym"];
	p_mmap_offset = funcSymbolMap["mmap"];
	p_munmap_offset = funcSymbolMap["munmap"];
	return ret;
}



int safe_load_libc64_modify_env_func_addr(
	unsigned int root_key,
	const char* so_path,
	size_t & p_mmap_offset,
	size_t & p_munmap_offset,
	size_t & p_getenv_offset,
	size_t & p_setenv_offset) {


	void * p_so_addr = get_module_base(-1, so_path);
	if (p_so_addr) {
		//自身有这个so
		void * p_so = dlopen(so_path, RTLD_NOW | RTLD_GLOBAL);
		if (p_so) {
			void * p_mmap = dlsym(p_so, "mmap");
			void * p_munmap = dlsym(p_so, "munmap");
			void * p_getenv = dlsym(p_so, "getenv");
			void * p_setenv = dlsym(p_so, "setenv");
			dlclose(p_so);
			if (p_mmap && p_munmap && p_getenv && p_setenv) {
				p_mmap_offset = ((size_t)p_mmap - (size_t)p_so_addr);
				p_munmap_offset = ((size_t)p_munmap - (size_t)p_so_addr);
				p_getenv_offset = ((size_t)p_getenv - (size_t)p_so_addr);
				p_setenv_offset = ((size_t)p_setenv - (size_t)p_so_addr);
				return 0;

			}
		}
	}

	std::map<std::string, uint64_t> funcSymbolMap;
	funcSymbolMap["getenv"] = 0;
	funcSymbolMap["setenv"] = 0;
	funcSymbolMap["mmap"] = 0;
	funcSymbolMap["munmap"] = 0;
	int ret = get_so_symbol_addr(so_path, funcSymbolMap);
	p_mmap_offset = funcSymbolMap["mmap"];
	p_munmap_offset = funcSymbolMap["munmap"];
	p_getenv_offset = funcSymbolMap["getenv"];
	p_setenv_offset = funcSymbolMap["setenv"];
	return ret;
}


//远程注入  
ssize_t inject_process64_run_cmd(
	unsigned int root_key,
	pid_t target_pid,
	const char *libc64_so_path,
	size_t & p_mmap_offset,
	size_t & p_munmap_offset,
	size_t & p_chdir_offset,
	size_t & p_clearenv_offset,
	size_t & p_setenv_offset,
	size_t & p_getuid_offset,
	size_t & p_setuid_offset,
	size_t & p_getgid_offset,
	size_t & p_setgid_offset,
/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/
	size_t & p_system_offset,
	size_t & p_pipe_offset,
	size_t & p_dup_offset,
	size_t & p_dup2_offset,
	size_t & p_read_offset,
	size_t & p_fcntl_offset,
	size_t & p_close_offset,
	const char *cmd, 
	const char* p_out_result_buf = NULL,
	size_t out_result_buf_size = 0,
	bool user_root_auth = true,
	bool after_recovery_last_uid = false,
	bool after_recovery_last_gid = false,
	const char * chdir_path = NULL,
	bool clear_env = false,
	std::vector<process64_env> *set_env = NULL)
{
	size_t write_len = strlen(cmd) + 1;
	size_t input_shell_buf_size = getpagesize();
	ssize_t ret = -230;
	size_t remote_libc64_handle = 0;
	size_t mmap_addr, munmap_addr, chdir_addr, clearenv_addr, setenv_addr, getuid_addr, setuid_addr, getgid_addr, setgid_addr,  /*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/, system_addr, pipe_addr, dup_addr, dup2_addr, read_addr, fcntl_addr, close_addr;
	uint8_t *map_base;
	unsigned int last_uid = 0;
	unsigned int last_gid = 0;
	size_t set_env_index = 0;

	struct pt_regs regs, original_regs;
	unsigned long parameters[10];
	char zero = '\0';

	int fd[2];
	int bak_out_fd;
	int bak_err_fd;
	int new_out_fd;
	int new_err_fd;
	int flags;


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

	//获取远程pid的某个模块的起始地址  
	remote_libc64_handle = (size_t)get_module_base(target_pid, libc64_so_path);
	if (remote_libc64_handle == 0) {
		TRACE("[+] get_module_base failed.\n");
		goto _deatch;
	}
	mmap_addr = p_mmap_offset ? remote_libc64_handle + p_mmap_offset: 0;
	munmap_addr = p_munmap_offset ? remote_libc64_handle + p_munmap_offset: 0;
	chdir_addr = p_chdir_offset ? remote_libc64_handle + p_chdir_offset : 0;
	clearenv_addr = p_clearenv_offset ? remote_libc64_handle + p_clearenv_offset : 0;
	setenv_addr = p_setenv_offset ? remote_libc64_handle + p_setenv_offset : 0;
	getuid_addr = p_getuid_offset ? remote_libc64_handle + p_getuid_offset : 0;
	setuid_addr = p_setuid_offset ? remote_libc64_handle + p_setuid_offset : 0;
	getgid_addr = p_getgid_offset ? remote_libc64_handle + p_getgid_offset : 0;
	setgid_addr = p_setgid_offset ? remote_libc64_handle + p_setgid_offset : 0;
/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/
	system_addr = p_system_offset ? remote_libc64_handle + p_system_offset: 0;
	pipe_addr = p_pipe_offset ? remote_libc64_handle + p_pipe_offset: 0;
	dup_addr = p_dup_offset ? remote_libc64_handle + p_dup_offset: 0;
	dup2_addr = p_dup2_offset ? remote_libc64_handle + p_dup2_offset: 0;
	read_addr = p_read_offset ? remote_libc64_handle + p_read_offset: 0;
	fcntl_addr = p_fcntl_offset ? remote_libc64_handle + p_fcntl_offset: 0;
	close_addr = p_close_offset ? remote_libc64_handle + p_close_offset: 0;

	TRACE("[+] Remote mmap address: %p\n", (void*)mmap_addr);
	TRACE("[+] Remote munmap address: %p\n", (void*)munmap_addr);
	TRACE("[+] Remote chdir address: %p\n", (void*)p_chdir_offset);
	TRACE("[+] Remote clearenv address: %p\n", (void*)p_clearenv_offset);
	TRACE("[+] Remote setenv address: %p\n", (void*)p_setenv_offset);
	TRACE("[+] Remote getuid address: %p\n", (void*)getuid_addr);
	TRACE("[+] Remote setuid address: %p\n", (void*)setuid_addr);
	TRACE("[+] Remote getgid address: %p\n", (void*)getgid_addr);
	TRACE("[+] Remote setgid address: %p\n", (void*)setgid_addr);
/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/
	TRACE("[+] Remote system address: %p\n", (void*)system_addr);
	TRACE("[+] Remote pipe address: %p\n", (void*)pipe_addr);
	TRACE("[+] Remote dup address: %p\n", (void*)dup_addr);
	TRACE("[+] Remote dup2 address: %p\n", (void*)dup2_addr);
	TRACE("[+] Remote read address: %p\n", (void*)read_addr);
	TRACE("[+] Remote fcntl address: %p\n", (void*)fcntl_addr);
	TRACE("[+] Remote close address: %p\n", (void*)close_addr);


	//判断是否需要提权
	if (user_root_auth && getuid_addr && /*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/)
	{
		if (ptrace_call_wrapper(target_pid, "getuid", (void*)getuid_addr, parameters, 0, &regs) == -1)
		{
			goto _recovery;
		}
		last_uid = (unsigned int)ptrace_retval(&regs);

		if (after_recovery_last_gid) //是否需要恢复gid
		{
			if (ptrace_call_wrapper(target_pid, "getgid", (void*)getgid_addr, parameters, 0, &regs) == -1)
			{
				goto _recovery;
			}
			last_gid = (unsigned int)ptrace_retval(&regs);
		}

		if (last_uid > 0) {
			//提权ROOT
			/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/
		}
	}



	/* call mmap (null, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC,
							 MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	匿名申请一块0x4000大小的内存
	*/
	parameters[0] = 0;  // addr      
	parameters[1] = (unsigned long)(input_shell_buf_size + out_result_buf_size); // size
	parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot      
	parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // flags      
	parameters[4] = 0; //fd      
	parameters[5] = 0; //offset      

	if (ptrace_call_wrapper(target_pid, "mmap", (void *)mmap_addr, parameters, 6, &regs) == -1)
	{
		goto _recovery;
	}

	//⑤从寄存器中获取mmap函数的返回值，即申请的内存首地址：  
	map_base = (uint8_t *)ptrace_retval(&regs);




	//判断是否需要改变工作目录
	if (chdir_path && chdir_addr)
	{
		//写KEY标志进mmap出来的内存
		ptrace_writedata(target_pid, map_base, (uint8_t *)chdir_path, strlen(chdir_path) + 1);
		parameters[0] = (unsigned long)map_base;
		if (ptrace_call_wrapper(target_pid, "chdir", (void*)chdir_addr, parameters, 1, &regs) == -1)
		{
			goto _recovery;
		}

	}

	//判断是否需要清除环境
	if (clear_env && clearenv_addr)
	{
		if (ptrace_call_wrapper(target_pid, "clearenv", (void*)clearenv_addr, parameters, 0, &regs) == -1)
		{
			goto _recovery;
		}

	}

	if (set_env) {
		for (process64_env env_info : *set_env) {
			//写KEY标志进mmap出来的内存
			ptrace_writedata(target_pid, map_base, (uint8_t *)env_info.key, strlen(env_info.key) + 1);

			uint8_t * val_mem_addr = map_base + strlen(env_info.key) + 1;

			//写VAL标志进mmap出来的内存
			ptrace_writedata(target_pid, val_mem_addr, (uint8_t *)env_info.value, strlen(env_info.value) + 1);

			parameters[0] = (unsigned long)map_base;
			parameters[1] = (unsigned long)(map_base + strlen(env_info.key) + 1);
			parameters[2] = 1;
			//执行setenv，等于setenv("XXX", "XXXXX", 1);
			if (ptrace_call_wrapper(target_pid, "setenv", (void*)setenv_addr, parameters, 3, &regs) == -1) {
				goto _recovery;
			}

		}
	}

	//将要注入的cmd命令写入前面mmap出来的内存
	if (write_len > input_shell_buf_size) { //输入命令太长了
		write_len = input_shell_buf_size;
	}
	ptrace_writedata(target_pid, map_base, (uint8_t *)cmd, write_len);

	if (write_len == input_shell_buf_size) {
		ptrace_writedata(target_pid, (uint8_t *)((size_t)map_base + input_shell_buf_size - 1), (uint8_t *)&zero, 1);
	}

	if (p_out_result_buf)
	{
		parameters[0] = (unsigned long)map_base + input_shell_buf_size;
		//执行pipe，等于pipe(fd);
		if (ptrace_call_wrapper(target_pid, "pipe", (void *)pipe_addr, parameters, 1, &regs) == -1)
		{
			goto _recovery;
		}
		if ((uint8_t *)ptrace_retval(&regs)) {
			//pipe error
			TRACE("pipe error\n");
			goto _recovery;
		}
		TRACE("pipe success\n");

		ptrace_readdata(target_pid, (uint8_t *)parameters[0], (uint8_t *)&fd, sizeof(fd));
		TRACE("pipe fd[0]:%d, fd[1]:%d\n", fd[0], fd[1]);

		parameters[0] = STDOUT_FILENO;
		//执行int bak_out_fd = dup(STDOUT_FILENO);
		if (ptrace_call_wrapper(target_pid, "dup", (void *)dup_addr, parameters, 1, &regs) == -1)
		{
			goto _recovery;
		}
		bak_out_fd = (int)ptrace_retval(&regs);

		parameters[0] = STDERR_FILENO;
		//执行int bak_err_fd = dup(STDERR_FILENO);
		if (ptrace_call_wrapper(target_pid, "dup", (void *)dup_addr, parameters, 1, &regs) == -1)
		{
			goto _recovery;
		}
		bak_err_fd = (int)ptrace_retval(&regs);

		parameters[0] = fd[1];
		parameters[1] = STDOUT_FILENO;
		//执行int new_out_fd = dup2(fd_out[1], STDOUT_FILENO);
		if (ptrace_call_wrapper(target_pid, "dup2", (void *)dup2_addr, parameters, 2, &regs) == -1)
		{
			goto _recovery;
		}
		new_out_fd = (int)ptrace_retval(&regs);

		parameters[0] = fd[1];
		parameters[1] = STDERR_FILENO;
		//执行int new_err_fd = dup2(fd_err[1], STDERR_FILENO);
		if (ptrace_call_wrapper(target_pid, "dup2", (void *)dup2_addr, parameters, 2, &regs) == -1)
		{
			goto _recovery;
		}
		new_err_fd = (int)ptrace_retval(&regs);

		parameters[0] = (unsigned long)map_base;
		//执行system，等于system("xxxxxxxx");
		if (ptrace_call_wrapper(target_pid, "system", (void *)system_addr, parameters, 1, &regs) == -1)
		{
			return ret;
		}
		//获取system返回值
		//ret = (ssize_t)ptrace_retval(&regs);

		parameters[0] = fd[0];
		parameters[1] = F_GETFL;
		parameters[2] = 0;
		//执行flags = fcntl(fd[0],F_GETFL, 0);
		if (ptrace_call_wrapper(target_pid, "fcntl", (void *)fcntl_addr, parameters, 3, &regs) == -1)
		{
			goto _recovery;
		}
		flags = (ssize_t)ptrace_retval(&regs);
		if (flags == -1)
		{
			goto _recovery;
		}
		flags |= O_NONBLOCK; //把读管道设置成非阻塞，不然没输出的时候会一直卡死

		parameters[0] = fd[0];
		parameters[1] = F_SETFL;
		parameters[2] = flags;
		//执行flags = fcntl(fd,F_SETFL,flags);
		if (ptrace_call_wrapper(target_pid, "fcntl", (void *)fcntl_addr, parameters, 3, &regs) == -1)
		{
			goto _recovery;
		}
		if ((ssize_t)ptrace_retval(&regs) == -1)
		{
			goto _recovery;
		}


		parameters[0] = fd[0];
		parameters[1] = (unsigned long)map_base + input_shell_buf_size;
		parameters[2] = (unsigned long)out_result_buf_size - 1;
		//执行read(fd[0], p_result, size - 1);
		if (ptrace_call_wrapper(target_pid, "read", (void *)read_addr, parameters, 3, &regs) == -1)
		{
			goto _recovery;
		}

		memset((void*)p_out_result_buf, 0, out_result_buf_size);
		if ((ssize_t)ptrace_retval(&regs) > 0)
		{
			ptrace_readdata(target_pid, (uint8_t *)parameters[1], (uint8_t *)p_out_result_buf, out_result_buf_size - 1);
		}
		TRACE("system result: %s\n", p_out_result_buf);

		parameters[0] = bak_out_fd;
		parameters[1] = new_out_fd;
		//执行dup2(bak_out_fd,new_out_fd);
		if (ptrace_call_wrapper(target_pid, "dup2", (void *)dup2_addr, parameters, 2, &regs) == -1)
		{
			goto _recovery;
		}

		parameters[0] = bak_err_fd;
		parameters[1] = new_err_fd;
		//执行dup2(bak_err_fd, new_err_fd);
		if (ptrace_call_wrapper(target_pid, "dup2", (void *)dup2_addr, parameters, 2, &regs) == -1)
		{
			goto _recovery;
		}


		parameters[0] = fd[0];
		//执行close(fd[0]);
		if (ptrace_call_wrapper(target_pid, "close", (void *)close_addr, parameters, 1, &regs) == -1)
		{
			goto _recovery;
		}


		parameters[0] = fd[1];
		//执行close(fd[1]);
		if (ptrace_call_wrapper(target_pid, "close", (void *)close_addr, parameters, 1, &regs) == -1)
		{
			goto _recovery;
		}
	}
	else
	{
		parameters[0] = (unsigned long)map_base;
		//执行system，等于system("xxxxxxxx");
		if (ptrace_call_wrapper(target_pid, "system", (void *)system_addr, parameters, 1, &regs) == -1)
		{
			goto _recovery;
		}
		//获取system返回值
		//ret = (ssize_t)ptrace_retval(&regs);

	}

	//解除绑定内存
	parameters[0] = (unsigned long)map_base;// addr
	parameters[1] = (unsigned long)(input_shell_buf_size + out_result_buf_size); // size

	if (ptrace_call_wrapper(target_pid, "munmap", (void *)munmap_addr, parameters, 2, &regs) == -1)
	{
		goto _recovery;
	}

	//判断是否需要恢复权限
	if (user_root_auth && after_recovery_last_gid) //必须先恢复gid，再恢复uid，不然没权限
	{
		if (last_gid > 0) {
			parameters[0] = last_gid;
			if (ptrace_call_wrapper(target_pid, "setgid", (void*)setgid_addr, parameters, 1, &regs) == -1)
			{
				goto _recovery;
			}
		}
	}
	if (user_root_auth && after_recovery_last_uid)
	{
		if (last_uid > 0) {
			parameters[0] = last_uid;
			if (ptrace_call_wrapper(target_pid, "setuid", (void*)setuid_addr, parameters, 1, &regs) == -1)
			{
				goto _recovery;
			}
		}
	}

	ret = 0;
	//TRACE("Press enter to detach\n");
	//getchar();

	/* restore */
	//⑪恢复现场并退出ptrace:  
_recovery:	ptrace_setregs(target_pid, &original_regs);
_deatch:ptrace_detach(target_pid);

_ret:	return ret;
}




ssize_t inject_process_env64_PATH(
	int target_pid,
	const char *libc64_so_path,
	size_t & p_mmap_offset,
	size_t & p_munmap_offset,
	size_t & p_getenv_offset,
	size_t & p_setenv_offset,
	const char *add_path)
{
	size_t write_len = strlen(add_path) + 1;
	size_t input_env_buf_size = getpagesize();
	ssize_t ret = -231;
	size_t remote_libc64_handle = 0;
	size_t mmap_addr, munmap_addr, getenv_addr, setenv_addr;
	uint8_t *map_base;

	struct pt_regs regs, original_regs;
	unsigned long parameters[10];
	char zero = '\x00';
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


	//获取远程pid的某个模块的起始地址  
	remote_libc64_handle = (size_t)get_module_base(target_pid, libc64_so_path);
	if (remote_libc64_handle == 0) {
		TRACE("[+] get_module_base failed.\n");
		goto _deatch;
	}
	mmap_addr = p_mmap_offset ? remote_libc64_handle + p_mmap_offset : 0;
	munmap_addr = p_munmap_offset ? remote_libc64_handle + p_munmap_offset: 0;
	getenv_addr = p_getenv_offset ? remote_libc64_handle + p_getenv_offset: 0;
	setenv_addr = p_setenv_offset ? remote_libc64_handle + p_setenv_offset: 0;

	TRACE("[+] Remote mmap address: %p\n", (void*)mmap_addr);
	TRACE("[+] Remote munmap address: %p\n", (void*)munmap_addr);
	TRACE("[+] Remote getenv address: %p\n", (void*)getenv_addr);
	TRACE("[+] Remote setenv address: %p\n", (void*)setenv_addr);

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

	if (ptrace_call_wrapper(target_pid, "mmap", (void*)mmap_addr, parameters, 6, &regs) == -1)
	{
		goto _recovery;
	}

	//⑤从寄存器中获取mmap函数的返回值，即申请的内存首地址：  
	map_base = (uint8_t *)ptrace_retval(&regs);

	//写PATH标志进mmap出来的内存
	ptrace_writedata(target_pid, map_base, (uint8_t *)str_flag_path, strlen(str_flag_path) + 1);


	parameters[0] = (unsigned long)map_base;
	//执行getenv，等于getenv("PATH");
	if (ptrace_call_wrapper(target_pid, "getenv", (void*)getenv_addr, parameters, 1, &regs) == -1)
	{
		goto _recovery;
	}
	ret_getenv = (char *)ptrace_retval(&regs);
	if (!ret_getenv) {
		//getenv error
		TRACE("getenv error\n");
		goto _recovery;
	}

	strcat(cur_path, add_path);
	strcat(cur_path, ":");
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

	

	TRACE("[+] Remote cur path: %s\n", cur_path);

	//写PATH变量进mmap出来的内存
	ptrace_writedata(target_pid, map_base + strlen(str_flag_path) + 1, (uint8_t *)cur_path, strlen(cur_path) + 1);


	parameters[0] = (unsigned long)map_base;
	parameters[1] = (unsigned long)(map_base + strlen(str_flag_path) + 1);
	parameters[2] = 1;
	//执行setenv，等于setenv("PATH", "XXXXX", 1);
	if (ptrace_call_wrapper(target_pid, "setenv", (void*)setenv_addr, parameters, 3, &regs) == -1)
	{
		goto _recovery;
	}
	if (ptrace_retval(&regs)) {
		//setenv error
		TRACE("setenv error\n");
		goto _recovery;
	}

	//解除绑定内存（不知道为什么解除内存绑定会导致对方程序crash）
	parameters[0] = (unsigned long)map_base;// addr
	parameters[1] = (unsigned long)(input_env_buf_size); // size

	if (ptrace_call_wrapper(target_pid, "munmap", (void*)munmap_addr, parameters, 2, &regs) == -1)
	{
		goto _recovery;
	}

	ret = 0;
	//TRACE("Press enter to detach\n");
	//getchar();

	/* restore */
	//⑪恢复现场并退出ptrace:  
_recovery:	ptrace_setregs(target_pid, &original_regs);
_deatch:ptrace_detach(target_pid);

_ret:	return ret;
}





//远程注入  
ssize_t inject_process64_so(
	pid_t target_pid,
	const char *libc64_so_path,
	size_t & p_dlopen_offset,
	size_t & p_dlsym_offset,
	size_t & p_mmap_offset,
	size_t & p_munmap_offset,
	const char *target_so_path,
	const char *target_so_fun_name)
{
	size_t target_so_path_len = strlen(target_so_path) + 1;
	size_t target_so_fun_name_len = strlen(target_so_fun_name) + 1;
	size_t input_shell_buf_size = getpagesize();
	ssize_t ret = -232;
	size_t remote_libc64_handle = 0;
	size_t dlopen_addr, dlsym_addr, mmap_addr, munmap_addr;
	uint8_t *map_base;
	void *p_target_so_handle = NULL;
	void *p_target_func = NULL;
	struct pt_regs regs, original_regs;
	unsigned long parameters[10];
	int flags;

	if (target_so_path_len > input_shell_buf_size || target_so_fun_name_len > input_shell_buf_size) { //输入太长了
		goto _ret;
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

	//获取远程pid的某个模块的起始地址  
	remote_libc64_handle = (size_t)get_module_base(target_pid, libc64_so_path);
	if (remote_libc64_handle == 0) {
		TRACE("[+] get_module_base failed.\n");
		goto _deatch;
	}
	dlopen_addr = p_dlopen_offset ? remote_libc64_handle + p_dlopen_offset : 0;
	dlsym_addr = p_dlsym_offset ? remote_libc64_handle + p_dlsym_offset : 0;
	mmap_addr = p_mmap_offset ? remote_libc64_handle + p_mmap_offset : 0;
	munmap_addr = p_munmap_offset ? remote_libc64_handle + p_munmap_offset : 0;

	TRACE("[+] Remote dlopen address: %p\n", (void*)p_dlopen_offset);
	TRACE("[+] Remote dlsym address: %p\n", (void*)p_dlsym_offset);
	TRACE("[+] Remote mmap address: %p\n", (void*)mmap_addr);
	TRACE("[+] Remote munmap address: %p\n", (void*)munmap_addr);

	/* call mmap (null, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC,
							 MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	匿名申请一块0x4000大小的内存
	*/
	parameters[0] = 0;  // addr      
	parameters[1] = (unsigned long)(input_shell_buf_size); // size
	parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot      
	parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // flags      
	parameters[4] = 0; //fd      
	parameters[5] = 0; //offset      

	if (ptrace_call_wrapper(target_pid, "mmap", (void *)mmap_addr, parameters, 6, &regs) == -1)
	{
		goto _recovery;
	}

	//⑤从寄存器中获取mmap函数的返回值，即申请的内存首地址：  
	map_base = (uint8_t *)ptrace_retval(&regs);

	//将要注入的so路径写入前面mmap出来的内存
	ptrace_writedata(target_pid, map_base, (uint8_t *)target_so_path, target_so_path_len);


	parameters[0] = (unsigned long)map_base;
	parameters[1] = (unsigned long)(RTLD_NOW | RTLD_GLOBAL);
	//执行dlopen，等于 p_target_so_handle = dlopen("xxxxxxx.so", RTLD_NOW | RTLD_GLOBAL);
	if (ptrace_call_wrapper(target_pid, "dlopen", (void *)dlopen_addr, parameters, 2, &regs) == -1)
	{
		goto _recovery;
	}
	p_target_so_handle = (void *)ptrace_retval(&regs);
	if (!p_target_so_handle) {
		//dlopen error
		TRACE("dlopen error\n");
		goto _recovery;
	}

	//将要注入的func名字写入前面mmap出来的内存
	ptrace_writedata(target_pid, map_base, (uint8_t *)target_so_fun_name, target_so_fun_name_len);

	parameters[0] = (unsigned long)p_target_so_handle;
	parameters[1] = (unsigned long)map_base;
	//执行p_target_func = dlsym(p_target_so_handle, "xxxxxxxx");
	if (ptrace_call_wrapper(target_pid, "dlsym", (void *)dlsym_addr, parameters, 2, &regs) == -1)
	{
		goto _recovery;
	}

	p_target_func = (void*)ptrace_retval(&regs);
	if (!p_target_func) {
		//dlsym error
		TRACE("dlsym error\n");
		goto _recovery;
	}

	if (ptrace_call_wrapper(target_pid, "hook_init", p_target_func, parameters, 0, &regs) == -1)
	{
		goto _recovery;
	}


	////解除绑定内存
	//parameters[0] = (unsigned long)map_base;// addr
	//parameters[1] = (unsigned long)input_shell_buf_size; // size

	//if (ptrace_call_wrapper(target_pid, "munmap", (void *)munmap_addr, parameters, 2, &regs) == -1)
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



ssize_t inject_process64_run_cmd_wrapper(
	unsigned int root_key, 
	pid_t target_pid, 
	const char *cmd, 
	const char* p_out_result_buf/* = NULL*/,
	size_t out_result_buf_size/* = 0*/,
	bool user_root_auth/* = true*/,
	bool after_recovery_last_uid/* = false*/,
	bool after_recovery_last_gid/* = false*/,
	const char * chdir_path /*= NULL*/,
	bool clear_env/* = false*/,
	std::vector<process64_env> *set_env /* = NULL*/)
{
	if (cmd == NULL || strlen(cmd) == 0) { return 0; }

	if (!p_out_result_buf) { out_result_buf_size = 0; }

	if (get_root(root_key) != 0) {
		return -241;
	}

	if (!is_disable_selinux_status()) {  //要关掉SELinux才能找到进程PID
		if (disable_selinux(root_key) != 0) {
			return -242;
		}
	}

	std::string target_process_libc_so_path = find_process_libc_so_path(target_pid);
	if (target_process_libc_so_path.empty()) {
		return -243;
	}
	TRACE("target_process_libc_so_path:%s\n", target_process_libc_so_path.c_str());

	size_t p_mmap_offset;
	size_t p_munmap_offset;
	size_t p_chdir_offset;
	size_t p_clearenv_offset;
	size_t p_setenv_offset;
	size_t p_getuid_offset;
	size_t p_setuid_offset;
	size_t p_getgid_offset;
	size_t p_setgid_offset;
/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/
	size_t p_system_offset;
	size_t p_pipe_offset;
	size_t p_dup_offset;
	size_t p_dup2_offset;
	size_t p_read_offset;
	size_t p_fcntl_offset;
	size_t p_close_offset;
	int ret = safe_load_libc64_run_cmd_func_addr(
		root_key,
		target_process_libc_so_path.c_str(),
		p_mmap_offset,
		p_munmap_offset,
		p_chdir_offset,
		p_clearenv_offset,
		p_setenv_offset,
		p_getuid_offset,
		p_setuid_offset,
		p_getgid_offset,
		p_setgid_offset,
/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/
		p_system_offset,
		p_pipe_offset,
		p_dup_offset,
		p_dup2_offset,
		p_read_offset,
		p_fcntl_offset,
		p_close_offset);

	if (ret != 0)
	{
		TRACE("safe_load_libc64_run_cmd_func_addr error:%d\n", ret);
		return ret;
	}
	TRACE("p_mmap_offset:%zu\n", p_mmap_offset);
	TRACE("p_munmap_offset:%zu\n", p_munmap_offset);
	TRACE("p_chdir_offset:%zu\n", p_chdir_offset);
	TRACE("p_clearenv_offset:%zu\n", p_clearenv_offset);
	TRACE("p_setenv_offset:%zu\n", p_setenv_offset);
	TRACE("p_getuid_offset:%zu\n", p_getuid_offset);
	TRACE("p_setuid_offset:%zu\n", p_setuid_offset);
	TRACE("p_getgid_offset:%zu\n", p_getgid_offset);
	TRACE("p_setgid_offset:%zu\n", p_setgid_offset);
/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/
	TRACE("p_system_offset:%zu\n", p_system_offset);
	TRACE("p_pipe_offset:%zu\n", p_pipe_offset);
	TRACE("p_dup_offset:%zu\n", p_dup_offset);
	TRACE("p_dup2_offset:%zu\n", p_dup2_offset);
	TRACE("p_read_offset:%zu\n", p_read_offset);
	TRACE("p_fcntl_offset:%zu\n", p_fcntl_offset);
	TRACE("p_close_offset:%zu\n", p_close_offset);

	if (inject_process64_run_cmd(
		root_key,
		target_pid,
		target_process_libc_so_path.c_str(),
		p_mmap_offset,
		p_munmap_offset,
		p_chdir_offset,
		p_clearenv_offset,
		p_setenv_offset,
		p_getuid_offset,
		p_setuid_offset,
		p_getgid_offset,
		p_setgid_offset,
/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/
		p_system_offset,
		p_pipe_offset,
		p_dup_offset,
		p_dup2_offset,
		p_read_offset,
		p_fcntl_offset,
		p_close_offset,
		cmd, p_out_result_buf,
		out_result_buf_size,
		user_root_auth,
		after_recovery_last_uid,
		after_recovery_last_gid,
		chdir_path,
		clear_env,
		set_env) != 0) {
		return -244;
	}
	return 0;
}


ssize_t safe_inject_process64_run_cmd_wrapper(
	unsigned int root_key,
	pid_t target_pid,
	const char *cmd,
	const char* p_out_result_buf/* = NULL*/,
	size_t out_result_buf_size/* = 0*/,
	bool user_root_auth/* = true*/,
	bool after_recovery_last_uid/* = false*/,
	bool after_recovery_last_gid/* = false*/,
	const char * chdir_path/* = NULL*/,
	bool clear_env/* = false*/,
	std::vector<process64_env> *set_env /* = NULL*/)
{
	if (cmd == NULL || strlen(cmd) == 0) { return 0; }
	int fd[2];
	if (pipe(fd))
	{
		return -251;
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		//fork error
		return -252;

	}
	else if (pid == 0) { /* 子进程 */
		close(fd[0]); //close read pipe
		
		int ret = 0;
		if (get_root(root_key) != 0) {
			ret = -253;
			write(fd[1], &ret, sizeof(ret));
			return ret;
		}

		if (!is_disable_selinux_status()) {  //要关掉SELinux才能找到进程PID
			if (disable_selinux(root_key) != 0) {
				ret = -254;
				write(fd[1], &ret, sizeof(ret));
				return ret;
			}
		}

		std::string target_process_libc_so_path = find_process_libc_so_path(target_pid);
		if (target_process_libc_so_path.empty()) {
			ret = -255;
			write(fd[1], &ret, sizeof(ret));
			return ret;
		}
		
		write(fd[1], &ret, sizeof(ret));
		if (!ret) {
			write(fd[1], target_process_libc_so_path.c_str(), target_process_libc_so_path.length() + 1);
		}
		close(fd[1]); //close write pipe
		_exit(0);
		return -256;
	}

	//父进程

	close(fd[1]); //close write pipe

	int status;
	/* 等待目标进程停止或终止. WUNTRACED - 解释见参考手册 */
	if (waitpid(pid, &status, WUNTRACED) < 0 && errno != EACCES) { return -6; }

	int ret = -257;
	read(fd[0], (void*)&ret, sizeof(ret));
	if (ret)
	{
		close(fd[0]); //close read pipe
		return ret;
	}

	char libc_path[1024] = { 0 };
	int index = 0;
	do
	{
		if (index >= sizeof(libc_path) - 1)
		{
			break;
		}
		read(fd[0], (void*)&libc_path[index], 1);

	} while (libc_path[index++] != '\x00');
	TRACE("target_process_libc_so_path:%s\n", libc_path);
	
	close(fd[0]); //close read pipe


	size_t p_mmap_offset;
	size_t p_munmap_offset;
	size_t p_chdir_offset;
	size_t p_clearenv_offset;
	size_t p_setenv_offset;
	size_t p_getuid_offset;
	size_t p_setuid_offset;
	size_t p_getgid_offset;
	size_t p_setgid_offset;
/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/
	size_t p_system_offset;
	size_t p_pipe_offset;
	size_t p_dup_offset;
	size_t p_dup2_offset;
	size_t p_read_offset;
	size_t p_fcntl_offset;
	size_t p_close_offset;
	ret = safe_load_libc64_run_cmd_func_addr(
		root_key,
		libc_path,
		p_mmap_offset,
		p_munmap_offset,
		p_chdir_offset,
		p_clearenv_offset,
		p_setenv_offset,
		p_getuid_offset,
		p_setuid_offset,
		p_getgid_offset,
		p_setgid_offset,
/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/
		p_system_offset,
		p_pipe_offset,
		p_dup_offset,
		p_dup2_offset,
		p_read_offset,
		p_fcntl_offset,
		p_close_offset);

	if (ret != 0)
	{
		TRACE("safe_load_libc64_run_cmd_func_addr error:%d\n", ret);
		return ret;
	}
	TRACE("p_mmap_offset:%zu\n", p_mmap_offset);
	TRACE("p_munmap_offset:%zu\n", p_munmap_offset);
	TRACE("p_chdir_offset:%zu\n", p_chdir_offset);
	TRACE("p_clearenv_offset:%zu\n", p_clearenv_offset);
	TRACE("p_setenv_offset:%zu\n", p_setenv_offset);
	TRACE("p_getuid_offset:%zu\n", p_getuid_offset);
	TRACE("p_setuid_offset:%zu\n", p_setuid_offset);
	TRACE("p_getgid_offset:%zu\n", p_getgid_offset);
	TRACE("p_setgid_offset:%zu\n", p_setgid_offset);
/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/
	TRACE("p_system_offset:%zu\n", p_system_offset);
	TRACE("p_pipe_offset:%zu\n", p_pipe_offset);
	TRACE("p_dup_offset:%zu\n", p_dup_offset);
	TRACE("p_dup2_offset:%zu\n", p_dup2_offset);
	TRACE("p_read_offset:%zu\n", p_read_offset);
	TRACE("p_fcntl_offset:%zu\n", p_fcntl_offset);
	TRACE("p_close_offset:%zu\n", p_close_offset);

	if (pipe(fd))
	{
		return -258;
	}
	if ((pid = fork()) < 0) {
		//fork error
		return -259;

	}
	else if (pid == 0) { /* 子进程 */
		close(fd[0]); //close read pipe

		int ret = 0;

		if (get_root(root_key) != 0) {
			ret = -260;
			write(fd[1], &ret, sizeof(ret));
			return ret;
		}

		if (!is_disable_selinux_status()) {  //要关掉SELinux才能找到adb进程PID
			if (disable_selinux(root_key) != 0) {
				ret = -261;
				write(fd[1], &ret, sizeof(ret));
				return ret;
			}
		}

		if (inject_process64_run_cmd(
			root_key,
			target_pid,
			libc_path,
			p_mmap_offset,
			p_munmap_offset,
			p_chdir_offset,
			p_clearenv_offset,
			p_setenv_offset,
			p_getuid_offset,
			p_setuid_offset,
			p_getgid_offset,
			p_setgid_offset,
/*TODO: Some variables are intentionally deleted here and will be supplemented on the release date*/
			p_system_offset,
			p_pipe_offset,
			p_dup_offset,
			p_dup2_offset,
			p_read_offset,
			p_fcntl_offset,
			p_close_offset,
			cmd, p_out_result_buf,
			out_result_buf_size,
			user_root_auth,
			after_recovery_last_gid,
			after_recovery_last_uid,
			chdir_path,
			clear_env,
			set_env) != 0) {
			ret = -262;
			write(fd[1], &ret, sizeof(ret));
			return ret;
		}

		write(fd[1], &ret, sizeof(ret));
		if (p_out_result_buf)
		{
			write(fd[1], p_out_result_buf, out_result_buf_size);
		}
		close(fd[1]); //close write pipe
		_exit(0);
		return -263;
	}
	//父进程

	close(fd[1]); //close write pipe

	/* 等待目标进程停止或终止. WUNTRACED - 解释见参考手册 */
	if (waitpid(pid, &status, WUNTRACED) < 0 && errno != EACCES) { return -6; }

	ret = -264;
	read(fd[0], (void*)&ret, sizeof(ret));
	if (ret == 0 && p_out_result_buf)
	{
		read(fd[0], (void*)p_out_result_buf, out_result_buf_size);
	}
	
	close(fd[0]); //close read pipe
	return ret;
	
}

ssize_t inject_process_env64_PATH_wrapper(unsigned int root_key, int target_pid, const char *add_path)
{
	if (get_root(root_key) != 0) {
		return -271;
	}


	if (!is_disable_selinux_status()) {  //要关掉SELinux才能找到进程PID
		if (disable_selinux(root_key) != 0) {
			return -272;
		}
	}

	/*
	安卓:
	/apex/com.android.runtime/lib64/bionic/libc.so
	/apex/com.android.runtime/bin/linker64

	Linux进程:
	/system/lib64/libc.so
	/system/bin/linker64

	init进程
	/system/lib64/bootstrap/libc.so
	/system/lib64/bootstrap/linker64
	*/
	std::string target_process_libc_so_path = find_process_libc_so_path(target_pid);
	if (target_process_libc_so_path.empty()) {
		return -273;
	}
	TRACE("target_process_libc_so_path:%s\n", target_process_libc_so_path.c_str());


	size_t p_mmap_offset;
	size_t p_munmap_offset;
	size_t p_getenv_offset;
	size_t p_setenv_offset;
	int ret = safe_load_libc64_modify_env_func_addr(
		root_key,
		target_process_libc_so_path.c_str(),
		p_mmap_offset,
		p_munmap_offset,
		p_getenv_offset,
		p_setenv_offset);

	if (ret != 0)
	{
		TRACE("safe_load_libc64_modify_env_func_addr error:%d\n", ret);
		return ret;
	}
	TRACE("p_mmap_offset:%zu\n", p_mmap_offset);
	TRACE("p_munmap_offset:%zu\n", p_munmap_offset);
	TRACE("p_getenv_offset:%zu\n", p_getenv_offset);
	TRACE("p_setenv_offset:%zu\n", p_setenv_offset);

	if (inject_process_env64_PATH(target_pid, target_process_libc_so_path.c_str(), p_mmap_offset, p_munmap_offset, p_getenv_offset, p_setenv_offset, add_path) != 0) {
		return -274;
	}
	return 0;
}


ssize_t safe_inject_process_env64_PATH_wrapper(unsigned int root_key, int target_pid, const char *add_path)
{
	int fd[2];
	if (pipe(fd))
	{
		return -281;
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		//fork error
		return -282;

	}
	else if (pid == 0) { /* 子进程 */
		close(fd[0]); //close read pipe

		int ret = 0;
		if (get_root(root_key) != 0) {
			ret = -283;
			write(fd[1], &ret, sizeof(ret));
			return ret;
		}

		if (!is_disable_selinux_status()) {  //要关掉SELinux才能找到进程PID
			if (disable_selinux(root_key) != 0) {
				ret = -284;
				write(fd[1], &ret, sizeof(ret));
				return ret;
			}
		}

		std::string target_process_libc_so_path = find_process_libc_so_path(target_pid);
		if (target_process_libc_so_path.empty()) {
			ret = -285;
			write(fd[1], &ret, sizeof(ret));
			return ret;
		}

		write(fd[1], &ret, sizeof(ret));
		if (!ret) {
			write(fd[1], target_process_libc_so_path.c_str(), target_process_libc_so_path.length() + 1);
		}
		close(fd[1]); //close write pipe
		_exit(0);
		return -286;
	}

	//父进程

	close(fd[1]); //close write pipe

	int status;
	/* 等待目标进程停止或终止. WUNTRACED - 解释见参考手册 */
	if (waitpid(pid, &status, WUNTRACED) < 0 && errno != EACCES) { return -287; }

	int ret = -288;
	read(fd[0], (void*)&ret, sizeof(ret));
	if (ret)
	{
		close(fd[0]); //close read pipe
		return ret;
	}

	char libc_path[1024] = { 0 };
	int index = 0;
	do
	{
		if (index >= sizeof(libc_path) - 1)
		{
			break;
		}
		read(fd[0], (void*)&libc_path[index], 1);

	} while (libc_path[index++] != '\x00');
	TRACE("target_process_libc_so_path:%s\n", libc_path);
	
	close(fd[0]); //close read pipe

	size_t p_mmap_offset;
	size_t p_munmap_offset;
	size_t p_getenv_offset;
	size_t p_setenv_offset;
	ret = safe_load_libc64_modify_env_func_addr(
		root_key,
		libc_path,
		p_mmap_offset,
		p_munmap_offset,
		p_getenv_offset,
		p_setenv_offset);

	if (ret != 0)
	{
		TRACE("safe_load_libc64_modify_env_func_addr error:%d\n", ret);
		return ret;
	}
	TRACE("p_mmap_offset:%zu\n", p_mmap_offset);
	TRACE("p_munmap_offset:%zu\n", p_munmap_offset);
	TRACE("p_getenv_offset:%zu\n", p_getenv_offset);
	TRACE("p_setenv_offset:%zu\n", p_setenv_offset);


	if (pipe(fd))
	{
		return -289;
	}
	if ((pid = fork()) < 0) {
		//fork error
		return -290;

	}
	else if (pid == 0) { /* 子进程 */
		close(fd[0]); //close read pipe

		int ret = 0;

		if (get_root(root_key) != 0) {
			ret = -291;
			write(fd[1], &ret, sizeof(ret));
			return ret;
		}

		if (!is_disable_selinux_status()) {  //要关掉SELinux才能找到adb进程PID
			if (disable_selinux(root_key) != 0) {
				ret = -292;
				write(fd[1], &ret, sizeof(ret));
				return ret;
			}
		}

		if (inject_process_env64_PATH(target_pid, libc_path, p_mmap_offset, p_munmap_offset, p_getenv_offset, p_setenv_offset, add_path) != 0) {
			ret = -293;
			write(fd[1], &ret, sizeof(ret));
			return ret;
		}

		write(fd[1], &ret, sizeof(ret));
		close(fd[1]); //close write pipe
		_exit(0);
		return -294;
	}
	//父进程

	close(fd[1]); //close write pipe

	/* 等待目标进程停止或终止. WUNTRACED - 解释见参考手册 */
	if (waitpid(pid, &status, WUNTRACED) < 0 && errno != EACCES) { return -6; }

	ret = -295;
	read(fd[0], (void*)&ret, sizeof(ret));
	
	close(fd[0]); //close read pipe
	return ret;
}


ssize_t inject_process64_so_wrapper(unsigned int root_key, pid_t target_pid, const char *p_target_so_path, const char* p_target_so_func_name)
{
	if (get_root(root_key) != 0) {
		return -301;
	}

	if (!is_disable_selinux_status()) {  //要关掉SELinux才能找到进程PID
		if (disable_selinux(root_key) != 0) {
			return -302;
		}
	}

	std::string target_process_libc_so_path = find_process_libc_so_path(target_pid);
	if (target_process_libc_so_path.empty()) {
		return -303;
	}
	TRACE("target_process_libc_so_path:%s\n", target_process_libc_so_path.c_str());

	size_t p_dlopen_offset;
	size_t p_dlsym_offset;
	size_t p_mmap_offset;
	size_t p_munmap_offset;
	int ret = safe_load_libc64_so_inject_func_addr(
		root_key,
		target_process_libc_so_path.c_str(),
		p_dlopen_offset,
		p_dlsym_offset,
		p_mmap_offset,
		p_munmap_offset);

	if (ret != 0)
	{
		TRACE("safe_load_libc64_so_inject_func_addr error:%d\n", ret);
		return ret;
	}
	TRACE("p_dlopen_offset:%zu\n", p_dlopen_offset);
	TRACE("p_dlsym_offset:%zu\n", p_dlsym_offset);
	TRACE("p_mmap_offset:%zu\n", p_mmap_offset);
	TRACE("p_munmap_offset:%zu\n", p_munmap_offset);

	if (inject_process64_so(
		target_pid,
		target_process_libc_so_path.c_str(),
		p_dlopen_offset,
		p_dlsym_offset,
		p_mmap_offset,
		p_munmap_offset,
		p_target_so_path,
		p_target_so_func_name) != 0) {
		return -304;
	}
	return 0;
}


ssize_t safe_inject_process64_so_wrapper(unsigned int root_key, pid_t target_pid, const char *p_target_so_path, const char* p_target_so_func_name)
{
	int fd[2];
	if (pipe(fd))
	{
		return -311;
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		//fork error
		return -312;

	}
	else if (pid == 0) { /* 子进程 */
		close(fd[0]); //close read pipe
		
		int ret = 0;
		if (get_root(root_key) != 0) {
			ret = -313;
			write(fd[1], &ret, sizeof(ret));
			return ret;
		}

		if (!is_disable_selinux_status()) {  //要关掉SELinux才能找到进程PID
			if (disable_selinux(root_key) != 0) {
				ret = -314;
				write(fd[1], &ret, sizeof(ret));
				return ret;
			}
		}

		std::string target_process_libc_so_path = find_process_libc_so_path(target_pid);
		if (target_process_libc_so_path.empty()) {
			ret = -315;
			write(fd[1], &ret, sizeof(ret));
			return ret;
		}
		
		write(fd[1], &ret, sizeof(ret));
		if (!ret) {
			write(fd[1], target_process_libc_so_path.c_str(), target_process_libc_so_path.length() + 1);
		}
		close(fd[1]); //close write pipe
		_exit(0);
		return -316;
	}

	//父进程

	close(fd[1]); //close write pipe

	int status;
	/* 等待目标进程停止或终止. WUNTRACED - 解释见参考手册 */
	if (waitpid(pid, &status, WUNTRACED) < 0 && errno != EACCES) { return -6; }

	int ret = -317;
	read(fd[0], (void*)&ret, sizeof(ret));
	if (ret)
	{
		close(fd[0]); //close read pipe
		return ret;
	}

	char libc_path[1024] = { 0 };
	int index = 0;
	do
	{
		if (index >= sizeof(libc_path) - 1)
		{
			break;
		}
		read(fd[0], (void*)&libc_path[index], 1);

	} while (libc_path[index++] != '\x00');
	TRACE("target_process_libc_so_path:%s\n", libc_path);
	
	close(fd[0]); //close read pipe


	size_t p_dlopen_offset;
	size_t p_dlsym_offset;
	size_t p_mmap_offset;
	size_t p_munmap_offset;
	ret = safe_load_libc64_so_inject_func_addr(
		root_key,
		libc_path,
		p_dlopen_offset,
		p_dlsym_offset,
		p_mmap_offset,
		p_munmap_offset);

	if (ret != 0)
	{
		TRACE("safe_load_libc64_so_inject_func_addr error:%d\n", ret);
		return ret;
	}
	TRACE("p_dlopen_offset:%zu\n", p_dlopen_offset);
	TRACE("p_dlsym_offset:%zu\n", p_dlsym_offset);
	TRACE("p_mmap_offset:%zu\n", p_mmap_offset);
	TRACE("p_munmap_offset:%zu\n", p_munmap_offset);

	if (pipe(fd))
	{
		return -318;
	}
	if ((pid = fork()) < 0) {
		//fork error
		return -319;

	}
	else if (pid == 0) { /* 子进程 */
		close(fd[0]); //close read pipe

		int ret = 0;

		if (get_root(root_key) != 0) {
			ret = -320;
			write(fd[1], &ret, sizeof(ret));
			return ret;
		}

		if (!is_disable_selinux_status()) {  //要关掉SELinux才能找到adb进程PID
			if (disable_selinux(root_key) != 0) {
				ret = -321;
				write(fd[1], &ret, sizeof(ret));
				return ret;
			}
		}

		if (inject_process64_so(
			target_pid,
			libc_path,
			p_dlopen_offset,
			p_dlsym_offset,
			p_mmap_offset,
			p_munmap_offset,
			p_target_so_path,
			p_target_so_func_name) != 0) {
			ret = -322;
			write(fd[1], &ret, sizeof(ret));
			return ret;
		}

		write(fd[1], &ret, sizeof(ret));
		close(fd[1]); //close write pipe
		_exit(0);
		return -323;
	}
	//父进程

	close(fd[1]); //close write pipe

	/* 等待目标进程停止或终止. WUNTRACED - 解释见参考手册 */
	if (waitpid(pid, &status, WUNTRACED) < 0 && errno != EACCES) { return -6; }

	ret = -324;
	read(fd[0], (void*)&ret, sizeof(ret));
	
	close(fd[0]); //close read pipe
	return ret;
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
int kill_process_ex(unsigned int root_key, const std::vector<pid_t> & vpid) {
	std::string kill_cmd;
	for (pid_t t : vpid) {
		kill_cmd += "kill -9 ";
		kill_cmd += std::to_string(t);
		kill_cmd += ";";
	}
	return run_normal_cmd(root_key, kill_cmd.c_str());
}
int safe_kill_process_ex(unsigned int root_key, const std::vector<pid_t> & vpid) {
	std::string kill_cmd;
	for (pid_t t : vpid) {
		kill_cmd += "kill -9 ";
		kill_cmd += std::to_string(t);
		kill_cmd += ";";
	}
	return safe_run_normal_cmd(root_key, kill_cmd.c_str());
}