#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
int find_cmdline_process(const char* target_cmdline)
{
	int id;
	pid_t pid = -1;
	DIR* dir;
	FILE *fp;
	char filename[32];
	char cmdline[256];

	struct dirent * entry;
	dir = opendir("/proc");
	if (dir == NULL)
		return -1;

	while ((entry = readdir(dir)) != NULL) {
		// 如果读取到的是"."或者".."则跳过，读取到的不是文件夹名字也跳过
		if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
			continue;
		}
		else if (entry->d_type != DT_DIR) {
			continue;
		}
		else if (strspn(entry->d_name, "1234567890") != strlen(entry->d_name)) {
			continue;
		}

		id = atoi(entry->d_name);
		if (id != 0) {
			sprintf(filename, "/proc/%d/cmdline", id);
			fp = fopen(filename, "r");
			if (fp) {
				fgets(cmdline, sizeof(cmdline), fp);
				fclose(fp);
				//TRACE("[+] find %d process cmdline: %s\n", id, cmdline);
				if (strstr(cmdline, target_cmdline)) {
					/* process found */
					pid = id;
					break;
				}
			}
		}
	}

	closedir(dir);
	return pid;
}
