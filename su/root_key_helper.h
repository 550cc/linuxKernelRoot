#ifndef _SOCKET_ID_HELPER_H_
#define _SOCKET_ID_HELPER_H_
#include <unistd.h>
#include <string.h>
#include <sstream>
#include "base64.h"
static inline unsigned int get_tmp_root_key(const char* myself_path) {

	//1.取路径尾巴
	unsigned int key = 0;
	const char* head_flag = "/su_";
	size_t len = strlen(head_flag);
	char *pstart = strstr((char*)myself_path, head_flag);
	if (!pstart) {
		return 0;
	}
	pstart += len;

	size_t copy_len;
	char *pend = strstr(pstart, "/");
	if (pend) {
		copy_len = pend - pstart;
	}
	else {
		copy_len = strlen(pstart);
	}
	char buf[256] = { 0 };
	memcpy(buf, pstart, copy_len);
	buf[sizeof(buf) - 1] = '\0';

	//2.base64解密
	std::string base64 = base64_decode(buf);

	//3.截止A字母
	size_t n = base64.find("A");
	if (n == -1) {
		return 0;
	}
	base64 = base64.substr(0, n);

	//4.取出KEY
	std::stringstream sstrConvert;
	sstrConvert << base64;
	sstrConvert >> key;
	return key;
}

#endif /* _SOCKET_ID_HELPER_H_ */
