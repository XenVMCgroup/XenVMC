#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h> 
#include <sys/types.h>
#include <netinet/tcp.h>	// for TCP_NODEALY
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

int init_socket(int port)
{
	int sock;

	struct sockaddr_in server_addr;

	if((sock=socket(PF_INET, SOCK_STREAM,0))<0){
		printf("init_socket:socket() error.\n");
		return -1;		
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(port);

	if(bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr))<0)
	{
		printf("init_socket : bind() error\n");
		close(sock);
		return -2;
	}

	if(listen(sock,5) < 0)
	{
		printf("init_socket : listen() error\n");
		close(sock);
		return -3;
	}

	return sock;
}

int done = 0;

void sig_handler(int signo) {
	done = 1;
	printf("sig %d caught\n", signo);
}

int xwayd_accept(int daemon_port) {
	int server_sock, client_sock;
	struct sockaddr_in client_addr;
	int sin_size;
	int    n;
	int dev_fd;

	server_sock = init_socket(daemon_port);
	if (server_sock < 0) {
		printf("socket creation error\n");
		return -1;
	}

	signal(SIGTERM, sig_handler);

	dev_fd = open("/dev/xwaya", O_RDWR);
	if (dev_fd < 0) {
		printf("/dev/xwaya open: %s\n", strerror(errno));
		close(server_sock);
		exit(-1);
	}

	sin_size=sizeof(client_addr);
	
	while (!done) {
		client_sock=accept(server_sock,(struct sockaddr *)&client_addr,
								&sin_size);
		if (client_sock < 0){
			printf("main : accept() error. errno=%d\n", errno);
			close(server_sock);
			exit(-1);
		}	
		n = write(dev_fd, (char *) &client_sock, sizeof(client_sock));

		close(client_sock);
	}
	close(dev_fd);
	close(server_sock);

	return 0;
}

int main(int argc,char *argv[])
{
	int pid;

	if(argc != 2) {
		printf("Usage : %s <server port>\n",argv[0]);
		return -1;
	}

	xwayd_accept(atoi(argv[1]));

	return 0;
}

