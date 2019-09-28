#include <stdio.h>

#define PORT 6789
#define BUF_LEN 8192
#define QUIT_CODE 7777
#define CHANNEL_BLOCK 1
#define CHANNEL_PORT 2
#define CHANNEL_PASV 4

typedef struct {
    char dirs[16][32];
    char wdname[256];
    int ndir;
} WorkDir;

typedef struct {
    char verb[8];
    char arg[256];
} Command;

typedef struct {
    int status;
    int hasMsg;
    char msg[256];
} Response;

typedef struct {
    int ip[6];
    int port;
    char ipname[20];
} Address;

typedef struct {
    Address addr;
    struct sockaddr_in sock;
    int connfd;
} SockPort;


void error(const char* msg);
void info(const char* msg);
void debug(const char* msg);

int eq(const char* s1, const char* s2);

struct sockaddr_in buildSockAddr(const char* pip, int port);
int createSock();
int listenTo(SockPort* psp);
int connectTo(SockPort* psp);

Address parseIPStr(const char* ips);

int sendStr(int sockfd, const char* str);
int sendRes(int sockfd, Response* pres);

int updateWd(WorkDir* wd, char *arg);
Command parse(const char* argStr);