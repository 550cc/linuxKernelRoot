#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "su_daemon.h"
#include "su_client.h"

int main(int argc, char *argv[])
{
	return argc == 2 && strcmp(argv[1], "--daemon") == 0 ?
		su_daemon_main() : su_client_main(argc, argv);
}
