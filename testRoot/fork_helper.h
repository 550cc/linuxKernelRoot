#ifndef FORK_HELPER_H_
#define FORK_HELPER_H_
#include <unistd.h>
static inline void force_kill_myself(void) {
	char* p = NULL;
	*p =1;
	exit(0);
}
#endif /* FORK_HELPER_H_ */
