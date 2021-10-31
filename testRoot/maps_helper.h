#ifndef MAPS_HELPER_H_
#define MAPS_HELPER_H_
#include "testRoot.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>


static std::string find_process_libc_so_path(pid_t pid) {
	char line[1024] = { 0 };
	std::string so_path;
	char filename[32];
	if (pid < 0) {
		/* self process */
		snprintf(filename, sizeof(filename), "/proc/self/maps");
	}
	else {
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	}
	FILE * fp = fopen(filename, "r");
	if (fp != NULL) {
		while (fgets(line, sizeof(line), fp)) {
			if (strstr(line, "libc.so")) {

				char * start = strstr(line, "/");
				if (start)
				{
					start[strlen(start) - 1] = '\0';
					so_path = start;
				}
				break;
			}
		}

		fclose(fp);
	}

	return so_path;
}


//显然，这里面核心的就是get_module_base函数：  
/*
此函数的功能就是通过遍历/proc/pid/maps文件，来找到目的module_name的内存映射起始地址。
由于内存地址的表达方式是startAddrxxxxxxx-endAddrxxxxxxx的，所以会在后面使用strtok(line,"-")来分割字符串
如果pid = -1,表示获取本地进程的某个模块的地址，
否则就是pid进程的某个模块的地址。
*/

static void* get_module_base(pid_t pid, const char* module_name)
{
	FILE *fp;
	long addr = 0;
	char *pch;
	char filename[32];
	char line[1024];

	if (pid < 0) {
		/* self process */
		snprintf(filename, sizeof(filename), "/proc/self/maps");
	}
	else {
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	}

	fp = fopen(filename, "r");

	if (fp != NULL) {
		while (fgets(line, sizeof(line), fp)) {
			if (strstr(line, module_name)) {
				//分解字符串为一组字符串。line为要分解的字符串，"-"为分隔符字符串。  
				pch = strtok(line, "-");
				//将参数pch字符串根据参数base(表示进制)来转换成无符号的长整型数    
				addr = strtoull(pch, NULL, 16);

				if (addr == 0x8000)
					addr = 0;

				break;
			}
		}

		fclose(fp);
	}

	return (void *)addr;
}

/*
该函数为一个封装函数，通过调用get_module_base函数来获取目的进程的某个模块的起始地址，然后通过公式计算出指定函数在目的进程的起始地址。
*/
static void* get_remote_addr(pid_t target_pid, const char* module_name, void* local_addr)
{
	void* local_handle, *remote_handle;

	//获取本地某个模块的起始地址  
	local_handle = get_module_base(-1, module_name);
	if (local_handle == NULL) {
		return local_handle;
	}

	//获取远程pid的某个模块的起始地址  
	remote_handle = get_module_base(target_pid, module_name);

	TRACE("[+] get_remote_addr: local[%p], remote[%p]\n", local_handle, remote_handle);
	/*这需要我们好好理解：local_addr - local_handle的值为指定函数(如mmap)在该模块中的偏移量，然后再加上rempte_handle，结果就为指定函数在目的进程的虚拟地址*/
	void * ret_addr = (void *)((uintptr_t)local_addr + (uintptr_t)remote_handle - (uintptr_t)local_handle);

	return ret_addr;
}

#endif /* MAPS_HELPER_H_ */
