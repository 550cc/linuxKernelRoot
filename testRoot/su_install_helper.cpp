#include "su_install_helper.h"
#include "kernel_root_helper.h"
#include "testRoot.h"
#include "../su/root_key_helper.h"
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <sys/stat.h> 
#include <sys/types.h>
#include <sys/xattr.h>

/*
 * xattr name for SELinux attributes.
 * This may have been exported via Kernel uapi header.
 */
#ifndef XATTR_NAME_SELINUX
#define XATTR_NAME_SELINUX "security.selinux"
#endif

const char* check_file_list[] = {
	"su",
};
std::string get_child_su_hidden_path(const char* myself_path) {

	std::string id;
	DIR* dir;
	FILE *fp;
	struct dirent * entry;
	const char* su_head = "su_";

	dir = opendir(myself_path);
	if (dir == NULL)
		return id;

	while ((entry = readdir(dir)) != NULL) {
		// 如果读取到的是"."或者".."则跳过，读取到的不是文件夹名字也跳过
		if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
			continue;
		}
		else if (entry->d_type != DT_DIR) {
			continue;
		}
		else if (strlen(entry->d_name) <= strlen(su_head)) {
			continue;
		}
		char * p_id = strstr(entry->d_name, su_head);
		if (!p_id) {
			continue;
		}
		p_id += strlen(su_head);
		id = myself_path;
		id += "/";
		id += entry->d_name;
		break;
	}
	closedir(dir);
	return id;

}
/*生成一个长度为n的包含字符和数字的随机字符串*/
void rand_str(char* dest, int n)
{
	int i, randno;
	char stardstring[63] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	srand((unsigned)time(NULL));
	for (i = 0; i < n; i++)
	{
		randno = rand() % 62;
		*dest = stardstring[randno];
		dest++;
	}
	*dest = '\0';
}

std::string create_su_hidden_path(const char* myself_path, unsigned int root_key) {

	//1.生成一个guid
	char guid[16 + 1] = { 0 };
	rand_str(guid, sizeof(guid) - 1);

	//2.将root_key密码写前面，加A字幕，加guid
	std::stringstream sstrBuf;
	sstrBuf << root_key << "A" << guid;
	
	//3.base64加密
	std::string base64 = base64_encode((const unsigned char*)sstrBuf.str().c_str(), sstrBuf.str().length());

	//4.拼接进路径
	std::string file_path = myself_path;
	file_path += "/su_";
	file_path += base64;
	if (mkdir(file_path.c_str(), 0755)) {
		TRACE("create_su_hidden_path error:%s\n", file_path.c_str());
		return {};
	}
	if (chmod(file_path.c_str(), 0777)) {
		TRACE("chmod error:%s\n", file_path.c_str());
		return {};
	}
	return file_path;

}
bool check_su_file_exist(const char* path) {

	std::string str_path = path;
	for (size_t i = 0; i < sizeof(check_file_list) / sizeof(check_file_list[0]); i++) {
		if (access(std::string(str_path + "/" + check_file_list[i]).c_str(), F_OK)) {
			TRACE("check_su_file_exist could not found %s.\n", check_file_list[i]);
			return false;
		}
	}
	return true;
}
bool set_su_file_access_mode(const char* path) {

	std::string str_path = path;
	for (size_t i = 0; i < sizeof(check_file_list) / sizeof(check_file_list[0]); i++) {
		std::string str_target_file_path = std::string(str_path + "/" + check_file_list[i]);
		if (chmod(str_target_file_path.c_str(), 0777)) {
			TRACE("set_su_file_access_mode could not found %s.\n", check_file_list[i]);
			return false;
		}
		const char* selinux_file_flag = "u:object_r:system_file:s0";
		if (setxattr(str_target_file_path.c_str(), XATTR_NAME_SELINUX, selinux_file_flag, strlen(selinux_file_flag) + 1, 0)) {
			TRACE("setxattr error %s.\n", str_target_file_path.c_str());
			return false;
		}

	}
	return true;
}
bool move_su_file_to_su_hidden_path(const char* source_path, const char* target_path) {

	std::string str_source_path = source_path;
	std::string str_target_path = target_path;
	for (size_t i = 0; i < sizeof(check_file_list) / sizeof(check_file_list[0]); i++) {

		std::string old_file_path = std::string(str_source_path + "/" + check_file_list[i]);
		std::string new_file_path = std::string(str_target_path + "/" + check_file_list[i]);
		if (access(old_file_path.c_str(), F_OK)) {
			TRACE("move_su_file_to_su_hidden_path could not found %s.\n", old_file_path.c_str());
			return false;
		}
		std::fstream file1;
		file1.open(old_file_path.c_str(), std::ios::binary | std::ios::in | std::ios::ate); //打开时指针在文件尾
		if (!file1.is_open()) {
			TRACE("Could not open file %s.\n", old_file_path.c_str());
			return false;
		}
		size_t length = file1.tellg();
		std::unique_ptr<char[]> up_new_file_data = std::make_unique<char[]>(length);
		file1.seekg(0);
		file1.read(up_new_file_data.get(), length); //二进制只能用这个读
		file1.close();


		std::fstream file2;
		file2.open(new_file_path.c_str(), std::ios::binary | std::ios::out);
		if (!file2.is_open()) {
			TRACE("Could not open file %s.\n", new_file_path.c_str());
			return false;
		}
		file2.write(up_new_file_data.get(), length);   //二进制只能用这个写
		file2.close();

		if (chmod(new_file_path.c_str(), 0777)) {
			TRACE("Could not chmod file %s.\n", new_file_path.c_str());
			return false;
		}
	}
	return true;
}
bool del_su_file(const char* path) {

	std::string str_path = path;
	for (size_t i = 0; i < sizeof(check_file_list) / sizeof(check_file_list[0]); i++) {
		std::string file_path = std::string(str_path + "/" + check_file_list[i]);
		TRACE("del_su_file:%s\n", file_path.c_str());
		remove(file_path.c_str());
	}
	return true;
}
int install_su_tools(unsigned int root_key, const char* base_path, std::string & su_hidden_path) {

	if (get_root(root_key) != 0) {
		return -501;
	}

	if (!is_disable_selinux_status()) {
		if (disable_selinux(root_key) != 0) {
			return -502;
		}
	}

	//1.获取su_xxx隐藏目录
	std::string _su_hidden_path = base_path;
	unsigned int tmp_root_key = get_tmp_root_key(base_path); //看看自身路径有没有
	if (tmp_root_key == 0) {
		_su_hidden_path = get_child_su_hidden_path(base_path); //没有再看看子目录

		if (_su_hidden_path.empty()) {
			//2.取不到，那就创建一个
			_su_hidden_path = create_su_hidden_path(base_path, root_key);
		}
		if (_su_hidden_path.empty()) {
			TRACE("su_hidden_path empty error\n");
			return -503;
		}
        su_hidden_path = _su_hidden_path + "/";

		//3.检查su_xxx目录下的文件是否齐全
		if (!check_su_file_exist(_su_hidden_path.c_str())) {
			//4.不齐全则开始补齐
			if (!check_su_file_exist(base_path)) {
				//自身目录都没有，怎么补过去
				TRACE("myself path su file not exist:%s\n", base_path);
				return -504;
			}
			//5.开始移动文件补齐到su_xxx目录
			if (!move_su_file_to_su_hidden_path(base_path, _su_hidden_path.c_str())) {
				TRACE("move_su_file_to_su_hidden_path error:%s -> %s\n", base_path, _su_hidden_path.c_str());
				return -505;
			}
		}
		//6.赋值文件运行权限
		if(!set_su_file_access_mode(_su_hidden_path.c_str())) {
			TRACE("set_su_file_access_mode error:%s\n", _su_hidden_path.c_str());
			return -506;
		}
		//7.从自身路径中删除文件，移除痕迹，防止被检测
		del_su_file(base_path);
	}
    su_hidden_path = _su_hidden_path + "/";
	return 0;
}

int safe_install_su_tools(unsigned int root_key, const char* base_path, std::string & su_hidden_path) {
	int fd[2];
	if (pipe(fd)) {
		return -431;
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		//fork error
		return -432;

	}
	else if (pid == 0) { /* 子进程 */
		close(fd[0]); //close read pipe
		pid_t ret = install_su_tools(root_key, base_path, su_hidden_path);
		write(fd[1], &ret, sizeof(ret));
		char buf[4096] = { 0 };
		strcpy(buf, su_hidden_path.c_str());
		write(fd[1], &buf, sizeof(buf));
		close(fd[1]); //close write pipe
		exit(0);
	}
	else { /*父进程*/

		close(fd[1]); //close write pipe

		int status;
		/* 等待目标进程停止或终止. WUNTRACED - 解释见参考手册 */
		if (waitpid(pid, &status, WNOHANG | WUNTRACED) < 0) { return -6; }

		pid_t ret = -433;
		read(fd[0], (void*)&ret, sizeof(ret));
		char buf[4096] = { 0 };
		read(fd[0], (void*)&buf, sizeof(buf));
		su_hidden_path = buf;
		close(fd[0]); //close read pipe
		return ret;
	}
	return -434;
}

int uninstall_su_tools(unsigned int root_key, const char* base_path) {

	if (get_root(root_key) != 0) {
		return -511;
	}

	if (!is_disable_selinux_status()) {
		if (disable_selinux(root_key) != 0) {
			return -512;
		}
	}
	//从自身路径中删除文件，移除痕迹，防止被检测
	del_su_file(base_path);

	do 
	{
		//获取su_xxx隐藏目录
		std::string _su_hidden_path = get_child_su_hidden_path(base_path); //没有再看看子目录
		if (_su_hidden_path.empty()) {
			break;
		}
		//取到了，再删
		del_su_file(_su_hidden_path.c_str());

		//文件夹也删掉
		std::string del_dir_cmd = "rm -rf ";
		del_dir_cmd += _su_hidden_path;
		int err = run_normal_cmd(root_key, del_dir_cmd.c_str());
		if (err) {
			return err;
		}

	} while (1);
	safe_enable_selinux(root_key);
	return 0;
}
int safe_uninstall_su_tools(unsigned int root_key, const char* base_path) {
	int fd[2];
	if (pipe(fd)) {
		return -520;
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		//fork error
		return -521;

	}
	else if (pid == 0) { /* 子进程 */
		close(fd[0]); //close read pipe
		int ret = uninstall_su_tools(root_key, base_path);
		write(fd[1], &ret, sizeof(ret));
		close(fd[1]); //close write pipe
		exit(0);
	}
	else { /*父进程*/

		close(fd[1]); //close write pipe

		int status;
		/* 等待目标进程停止或终止. WUNTRACED - 解释见参考手册 */
		if (waitpid(pid, &status, WNOHANG | WUNTRACED) < 0) { return -6; }

		int ret = -522;
		read(fd[0], (void*)&ret, sizeof(ret));
		close(fd[0]); //close read pipe
		return ret;
	}
	return -523;
}