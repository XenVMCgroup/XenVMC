#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define DEV		"/dev/xwaya"
#define ADD_IP	(-100)
#define DEL_IP	(-200)
/*
#define DEBUG

#ifdef DEBUG
#define dprintf(a)	printf(a)
#else
#define dprintf(a)	do{;}	while(0)
#endif
*/

int fd;
int buf[100];

static void usage() {
	printf("Usage\n");
	printf("\txway-admin [-l]    	 : listing current xway IP\n");
	printf("\txway-admin [-a] \"IP\" : adding IP address to xway enable list\n");
	printf("\txway-admin [-d] \"IP\" : deleting IP address from xway enable list\n");
}

static int open_dev() {
	int fd;
	fd = open(DEV, O_RDWR);
	if(fd < 0) {
		printf("/dev/xwaya open : %s\n", strerror(errno));
		return -1;
	}
	return fd;
}

static int listing_xwayip() {
	int i, ret;
	struct in_addr in;

	fd = open_dev();
	ret = read(fd, buf, 100);
	
	if(ret < 0) {
		printf("/dev/xwaya read : %s\n", strerror(errno));
		return -1;
	}

	if(buf[0] <= 0)
		printf("There is no xway enabled IP\n");

	for(i=0; i<buf[0]; i++) {
		in.s_addr = buf[i+1];
		
		printf("[%d] %s\n", i+1, inet_ntoa(in));
	}
	
	close(fd);

	return 0;
}

static int add_xwayip(char *str) {
	int ret;
	int buf[2];
	
	printf("add_xwayip, ipaddr = %s\n", str);

	fd = open_dev();
	buf[0] = ADD_IP;
	buf[1] = inet_addr(str);

	ret = write(fd, buf, sizeof(int)*2);

	if(ret < 0) {
		printf("/dev/xwaya write : %s\n", strerror(errno));
		return -1;
	}

	printf("add \"%s\" to xway enabled list\n", str);

	close(fd);

	return 0;
}


static int del_xwayip(char *str) {
	int ret;
	int buf[2];
	
	printf("del_xwayip, ipaddr = %s\n", str);

	fd = open_dev();
	buf[0] = DEL_IP;
	buf[1] = inet_addr(str);

	ret = write(fd, buf, sizeof(int)*2);

	if(ret < 0) {
		printf("/dev/xwaya write : %s\n", strerror(errno));
		return -1;
	}

	printf("delete \"%s\" to xway enabled list\n", str);

	close(fd);

	return 0;
}


int main(int argc, char *argv[]) {
	int err;
	char arg1[3];
	char arg2[20];
	
	if(argc < 2 || argc > 3) {
		usage();
		return 0;
	}

	if(argc == 2) {
		if(strcmp(argv[1], "-l")) {
			usage();
			return 0;
		}

		listing_xwayip();
		return 0;
	}

	if(strcmp(argv[1], "-a") && strcmp(argv[1], "-d")) {
		usage();
		return 0;
	}
		
	strcpy(arg2, argv[2]);

	printf("ip : %s\n", arg2);

	if(!strcmp(argv[1], "-a"))
		err = add_xwayip(arg2);

	else
		err = del_xwayip(arg2);	

	if(err)
		return -1;

	return 0;

}
