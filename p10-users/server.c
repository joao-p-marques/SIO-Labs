#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#define DATADIR "data"

int main(int argc, char** argv) {
    struct sockaddr_in saddr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    bzero((char *)& saddr, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port = htons((unsigned short) 1234);

    bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));

    while (1) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int n;
        char buf[1024];
        char fname[2048];
        bzero(fname, 2048);
        bzero(buf, 1024);

        int len = recvfrom(sockfd, buf, 1024, 0, (struct sockaddr *)&caddr, &clen);
        if (len <= 0)
            continue;

        sprintf(fname, "%s/%s", DATADIR, buf);
        FILE* fd = fopen(fname, "r");
		fprintf(stderr, "Serving file %s...", fname);
		if (fd == NULL) {
			fprintf(stderr, "Error\n");
			continue;
		}

        while (len > 0) {
            char data[1400];
            len = fread(data, 1, 1400, fd);
            if (len > 0)
                sendto(sockfd, data, len, 0, (struct sockaddr *)&caddr, clen);
        }
        fclose(fd);
    }
}
