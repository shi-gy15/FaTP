#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <unistd.h>
#include <errno.h>

#include <ctype.h>
#include <string.h>
#include <memory.h>
#include <stdio.h>
#include <dirent.h>
#include <time.h>

#include <arpa/inet.h>

// #include "operation.h"

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

void display(const char* s, const char* name) {
    printf("[DEBUG]: %s: [", name);
    char *p = s;
    while (*s != 0 || s - p < 8) {
        int normal = (*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9') || (*s == ' ');
        if (!normal) {
            printf("[%d], ", *s);
        }
        else
            printf("%c, ", *s);
        s++;
    }
    printf("], length %d\n", (int)(s - p));
}

void error(const char* msg) {
    printf("[ERROR] %s.\n", msg);
}

void info(const char* msg) {
    printf("[INFO] %s.\n", msg);
}

void debug(const char* msg) {
    printf("[DEBUG] %s.\n", msg);
}

int eq(const char* s1, const char* s2) {
    // display(s1, "s1");
    // display(s2, "s2");
    int res = strcmp(s1, s2);
    // printf("[DEBUG] comparing [%s] and [%s], result = %d\n", s1, s2, res);
    return res == 0;
}

struct sockaddr_in buildSockAddr(const char* pip, int port)
{
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

    if (pip != NULL) {
        if (inet_pton(AF_INET, pip, &addr.sin_addr) <= 0) {
            printf("Error inet_pton(): %s(%d)\n", strerror(errno), errno);
	        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        }
    }
    else {
	    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

	return addr;
}

int createSock() {
    int connfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connfd == -1) {
        printf("[ERROR] create socket fails: %s(%d)\n", strerror(errno), errno);
    }
    return connfd;
}

int listenTo(SockPort* psp) {
    if (bind(psp->connfd, (struct sockaddr*)&(psp->sock), sizeof(psp->sock)) == -1) {
        printf("Error bind(): %s(%d)\n", strerror(errno), errno);
        if(errno == 98){
            //Address already in use(98)
            return 233;
        }
        return 1;
    }

    if (listen(psp->connfd, 10) == -1) {
        printf("Error listen(): %s(%d)\n", strerror(errno), errno);
        return 1;
    }
    return 0;
}

int connectTo(SockPort* psp) {
    
    if (connect(psp->connfd, (struct sockaddr*)&psp->sock, sizeof(psp->sock)) < 0) {
        printf("Error connect(): %s(%d)\n", strerror(errno), errno);
        return 1;
    }

    return 0;

}



Address parseIPStr(const char* ips) {
    Address addr;
    // 127,0,0,1,233,233
    // int lastPos = 0;
    int curPos = 0;
    int val = 0;
    int pIp = 0;
    while (1) {
        if (ips[curPos] == ',' || ips[curPos] == '\0') {
            addr.ip[pIp] = val;
            pIp++;
            val = 0;
        }
        else {
            val *= 10;
            val += ips[curPos] - '0';
        }
        if (ips[curPos] == '\0')
            break;
        curPos++;
    }
    addr.port = addr.ip[4] * 256 + addr.ip[5];
    sprintf(addr.ipname, "%d.%d.%d.%d", addr.ip[0], addr.ip[1], addr.ip[2], addr.ip[3]);
    // printf("[DEBUG] addr: %d.%d.%d.%d:%d(%d,%d)\n", addr.ip[0], addr.ip[1], addr.ip[2], addr.ip[3], addr.port, addr.ip[4], addr.ip[5]);
    return addr;
}

int sendStr(int sockfd, const char* str) {
    int len = strlen(str);
    int sendLen = 0;
    int sended = -1;

    // do not examine if length exceeds buflen

    while (sendLen < len) {
        sended = send(sockfd, str + sendLen, len - sendLen, 0);
        if (sended == -1)
            break;

        sendLen += sended;
    }

    return (sended == -1) ? -1 : len;
}

int sendRes(int sockfd, Response* pres) {
    char reply[256] = {0};
    if (pres->hasMsg) {
        sprintf(reply, "%d %s\r\n", pres->status, pres->msg);
    }
    else {
        pres->msg[0] = '\0';
        // printf("asdsadasdasd%d, %s", pres->hasMsg, reply);
        sprintf(reply, "%d\r\n", pres->status);
    }
    printf("[DEBUG] Send response [%d: %s]\n", pres->status, pres->msg);
    sendStr(sockfd, reply);
}


int updateWd(WorkDir* ppwd, char* arg) {
    int len = strlen(arg);
    if (len == 0 || arg[0] == '/') {
        for (int i = 0; i < ppwd->ndir; i++) {
            strcpy(ppwd->dirs[i], "\0");
        }
        ppwd->ndir = 0;
        // strcpy(ppwd->ppwdname, "/");
        // return 0;
    }

    // if (len > 0 && arg[0] == '/') {
    //     // clean existing dirs
    //     for (int i = 0; i < ppwd->ndir; i++) {
    //         strcpy(ppwd->dirs[i], "\0");
    //     }
    //     ppwd->ndir = 0;
    // }
    int last = 0;
    int cur = 0;
    while (1) {
        if ((arg[cur] == '/' || arg[cur] == '\0')) {
            if (last < cur) {
                // if (strncmp(arg + last, "..", cur - last) == 0) {
                if (arg[last] == '.' && arg[last + 1] == '.') {
                    if (ppwd->ndir == 0)
                        ;
                    else {
                        strcpy(ppwd->dirs[ppwd->ndir - 1], "\0");
                        ppwd->ndir--;
                    }
                }
                else if (strncmp(arg + last, ".", cur - last) == 0) {
                    ;
                }
                else {
                    strncpy(ppwd->dirs[ppwd->ndir], arg + last, cur - last);
                    ppwd->dirs[ppwd->ndir][cur - last] = '\0';
                    // printf("asc%s\n", ppwd->dirs[ppwd->ndir]);
                    ppwd->ndir++;
                }
            }
            
            last = cur + 1;
        }
        if (arg[cur] == '\0')
            break;
        cur++;
    }

    if (ppwd->ndir == 0) {
        strcpy(ppwd->wdname, "/");
    }
    else {
        memset(ppwd->wdname, 0, sizeof(ppwd->wdname));
        int offset = 0;
        // printf("offset: %d\n", offset);
        for (int i = 0; i < ppwd->ndir; i++) {
            sprintf(ppwd->wdname + offset, "/%s", ppwd->dirs[i]);
            offset += strlen(ppwd->dirs[i]) + 1;
        }
    }

    return 0;
}


int splitSymbol(char ch) {
    // If ch is a split symbol
    // if true, return index, else return -1
    char ss[] = {' ', '\r', '\n', '\0'};
    for (int i = 0; i < 4; i++) {
        if (ch == ss[i])
            return i;
    }
    return -1;
}


Command parse(const char* argStr) {
    Command cmd;
    memset(&cmd, 0, sizeof(Command));
    int i = 0;
    char state = 'V';
    char ch = '\0';
    int argStartPos = 0;
    while (1) {
        ch = argStr[i];
        // printf("ch=%d\n", ch);
        switch (state) {
            case 'V':
                // if ss
                if (splitSymbol(ch) >= 0) {
                    // display(cmd.verb, "verb-before");
                    strncpy(cmd.verb, argStr, i);
                    cmd.verb[i] = 0;
                    // display(cmd.verb, "verb");
                    state = 'A';
                    argStartPos = i + 1;
                }
                // still a verb
                else {
                    ;
                }
                break;
            case 'A':
                if (splitSymbol(ch) >= 0) {
                    // reach the end
                    strncpy(cmd.arg, argStr + argStartPos, i - argStartPos);
                    cmd.arg[i - argStartPos] = '\0';
                    state = 'F';
                }
                else {
                    ;
                }
                break;
            case 'F':
                break;
            default:
                break;
        }
        if (ch == '\0')
            break;
        i++;
    }
    // strcpy(cmd.verb, "USER2");
    return cmd;
}


char username[32] = {0};
char password[32] = {0};
// char pwd[258] = {0};
int pid;

int channel = CHANNEL_BLOCK;

// Address* pPort = NULL;
SockPort sp;
WorkDir wd;

int switchMode() {
    switch (channel) {
        case CHANNEL_PORT:
            if (connectTo(&sp) != 0) {
                return -1;
            }
            return sp.connfd;
            break;
        case CHANNEL_PASV:
            return accept(sp.connfd, NULL, NULL);
            // printf("asd?%d\n", trfd);
            break;
        default:
            break;
    }
    return -1;
}


int handleUser(int connfd, Command* pcmd) {
    Response res;
    if (eq(pcmd->arg, "a")) {
        strcpy(username, pcmd->arg);
        res.status = 331;
        res.hasMsg = 1;
        strcpy(res.msg, "Enter password");
        sendRes(connfd, &res);
        return 0;
    }
    else {
        res.status = 530;
        res.hasMsg = 1;
        strcpy(res.msg, "Wrong username");
        sendRes(connfd, &res);
        return 1;
    }
}

int handlePassword(int connfd, Command* pcmd) {
    Response res;
    // printf("[DEBUG] Username: [%s], password: [%s]\n", username, password);
    if (eq(username, "a")) {
        if (eq(password, "\0")) {
            strcpy(password, pcmd->arg);
            res.status = 230;
            res.hasMsg = 1;
            sprintf(res.msg, "Successfully login with user [%s]", username);
            sendRes(connfd, &res);
            return 0;
        }
        else {
            res.status = 530;
            res.hasMsg = 1;
            strcpy(res.msg, "Alredy login");
            sendRes(connfd, &res);
            return 1;
        }
    }
    else {
        res.status = 530;
        res.hasMsg = 1;
        strcpy(res.msg, "Invalid user");
        sendRes(connfd, &res);
        return 1;
    }
}

int handleSystem(int connfd, Command* pcmd) {
    Response res;
    res.status = 211;
    res.hasMsg = 1;
    strcpy(res.msg, "Ubuntu-16.04");
    sendRes(connfd, &res);
    return 0;
}

int handleType(int connfd, Command* pcmd) {
    Response res;
    res.status = 200;
    res.hasMsg = 1;
    sprintf(res.msg, "Type set to %s", pcmd->arg);
    sendRes(connfd, &res);
    return 0;
}

int handlePwd(int connfd, Command* pcmd) {
    Response res;
    res.status = 257;
    res.hasMsg = 1;
    strcpy(res.msg, wd.wdname);
    sendRes(connfd, &res);
    return 0;
}

int handleCwd(int connfd, Command* pcmd) {
    updateWd(&wd, pcmd->arg);
    chdir(wd.wdname);
    Response res;
    res.status = 250;
    res.hasMsg = 1;
    strcpy(res.msg, wd.wdname);
    sendRes(connfd, &res);
    return 0;
}

int handlePort(int connfd, Command* pcmd) {
    channel = CHANNEL_PORT;

    sp.addr = parseIPStr(pcmd->arg);
    sp.connfd = createSock();
    sp.sock = buildSockAddr(sp.addr.ipname, sp.addr.port);
    
    Response res;
    res.status = 200;
    res.hasMsg = 0;
    sendRes(connfd, &res);
    return 0;
}

int handlePassive(int connfd, Command* pcmd) {
    channel = CHANNEL_PASV;
    srand((unsigned)time(NULL));
    int port = rand() % (65536 - 20000) + 20000;
    int p1 = port / 256;
    int p2 = port % 256;

    printf("[DEBUG] Passive apply port %d(%d, %d)\n", port, p1, p2);
    
    Response res;
    res.status = 227;
    res.hasMsg = 1;
    sprintf(res.msg, "%d,%d,%d,%d,%d,%d", 127, 0, 0, 1, p1, p2);

    sp.addr = parseIPStr(res.msg);
    sp.connfd = createSock();
    sp.sock = buildSockAddr(NULL, sp.addr.port);

    if (listenTo(&sp) != 0) {
        return 1;
    }

    sendRes(connfd, &res);
    return 0;
}

int handleList(int connfd, Command* pcmd) {

    int trfd = switchMode();

    // send response for start
    Response res;
    res.status = 150;
    res.hasMsg = 0;
    sendRes(connfd, &res);

    // tranfering list information
    DIR *dirp;
    struct dirent *dp;
    dirp = opendir(wd.wdname); //打开目录指针
    char buf[256] = {0};
    
    while ((dp = readdir(dirp)) != NULL) { //通过目录指针读目录
        sprintf(buf, ">-- %s\r\n", dp->d_name);
        sendStr(trfd, buf);
        // printf("%s", buf);
    }
    closedir(dirp); //关闭目录

    // send resposne for finish
    Response resFinish;
    resFinish.status = 226;
    resFinish.hasMsg = 1;
    strcpy(resFinish.msg, "List finish, connection closed");
    sendRes(connfd, &resFinish);

    if (channel == CHANNEL_PASV) {
        close(trfd);
        close(sp.connfd);
    }
    else {
        close(sp.connfd);
    }

    return 0;
}

int handleRetrieve(int connfd, Command* pcmd) {
    // TODO: support abs path
    char filename[512] = {0};
    sprintf(filename, "%s/%s", wd.wdname, pcmd->arg);

    // switch transfer mode
    int trfd = switchMode();

    // send response for start
    Response res;
    res.status = 150;
    res.hasMsg = 1;
    strcpy(res.msg, "Start transfering file");
    sendRes(connfd, &res);

    // send file
    FILE* f = fopen(filename, "rb");
    if(!f) {
        printf("Error fopen(), filename %s\n", filename);
    }
    char buf[BUF_LEN + 2];
    int nbytes;

    while (1) {
        nbytes = fread(buf, 1, BUF_LEN, f);
        // printf("[%d]", nbytes);
        if (nbytes > 0)
            send(trfd, buf, nbytes, 0);
        else
            break;
    }
    fclose(f);

    // send resposne for finish
    Response resFinish;
    resFinish.status = 226;
    resFinish.hasMsg = 1;
    strcpy(resFinish.msg, "File retrieve finish, connection closed");
    sendRes(connfd, &resFinish);

    if (channel == CHANNEL_PASV) {
        close(trfd);
        close(sp.connfd);
    }
    else {
        close(sp.connfd);
    }

    return 0;
}

int handleStore(int connfd, Command* pcmd) {
    // TODO: support abs path
    char filename[512] = {0};
    sprintf(filename, "%s/%s", wd.wdname, pcmd->arg);

    // switch transfer mode
    int trfd = switchMode();

    // send response for start
    Response res;
    res.status = 150;
    res.hasMsg = 1;
    strcpy(res.msg, "Start transfering file");
    sendRes(connfd, &res);

    FILE* f = fopen(filename, "wb");
    if(!f) {
        printf("Error fopen(), filename %s\n", filename);
    }
    char buf[BUF_LEN + 2];
    int nbytes;

    while (1) {
        nbytes = recv(trfd, buf, BUF_LEN, 0);
        // printf("[%d]", nbytes);
        if (nbytes < 0) {
            printf("Error in receiving file\n");
            break;
        }
        else if (nbytes == 0) {
            break;
        }
        else {
            fwrite(buf, sizeof(char), nbytes, f);
        }
    }
    fclose(f);

    // send resposne for finish
    Response resFinish;
    resFinish.status = 226;
    resFinish.hasMsg = 1;
    strcpy(resFinish.msg, "File store finish, connection closed");
    sendRes(connfd, &resFinish);

    if (channel == CHANNEL_PASV) {
        close(trfd);
        close(sp.connfd);
    }
    else {
        close(sp.connfd);
    }

    return 0;
}

int handleAbort(int connfd, Command* pcmd) {
    Response res;
    res.status = 226;
    res.hasMsg = 1;
    strcpy(res.msg, "Aborting");
    sendRes(connfd, &res);

    return QUIT_CODE;
}

int handleQuit(int connfd, Command* pcmd) {
    Response res;
    res.status = 200;
    res.hasMsg = 1;
    strcpy(res.msg, "Quit FaTP");
    sendRes(connfd, &res);

    return QUIT_CODE;
}


int dispatch(int connfd, char* argStr, int nbytes) {
    
    if (argStr[nbytes - 1] == '\n') {
        argStr[nbytes - 1] = '\0';
    }
    if (nbytes > 0 && (argStr[nbytes - 2] == '\r' || argStr[nbytes - 2] == '\n')) {
        argStr[nbytes - 2] = '\0';
    }
    // printf("[DEBUG] Dispath arg: [%s] with length [%d]\n", argStr, nbytes);
    // printf("[DEBUG] Get input string [%s].\n", argStr);
    Command cmd = parse(argStr);
    printf("[DEBUG] Get  command verb = [%s], arg = [%s].\n", cmd.verb, cmd.arg);
    
    if (eq(cmd.verb, "USER") == 1) {
        handleUser(connfd, &cmd);
    }
    else if (eq(cmd.verb, "PASS") == 1) {
        handlePassword(connfd, &cmd);
    }
    else if (eq(cmd.verb, "SYST") == 1) {
        handleSystem(connfd, &cmd);
    }
    else if (eq(cmd.verb, "TYPE") == 1) {
        handleType(connfd, &cmd);
    }
    else if (eq(cmd.verb, "PWD") == 1) {
        handlePwd(connfd, &cmd);
    }
    else if (eq(cmd.verb, "CWD") == 1) {
        handleCwd(connfd, &cmd);
    }
    else if (eq(cmd.verb, "PORT") == 1) {
        handlePort(connfd, &cmd);
    }
    else if (eq(cmd.verb, "LIST") == 1) {
        handleList(connfd, &cmd);
    }
    else if (eq(cmd.verb, "ABOR") == 1) {
        handleAbort(connfd, &cmd);
    }
    else if (eq(cmd.verb, "QUIT") == 1) {
        handleQuit(connfd, &cmd);
    }
    else if (eq(cmd.verb, "PASV") == 1) {
        handlePassive(connfd, &cmd);
    }
    else if (eq(cmd.verb, "RETR") == 1) {
        handleRetrieve(connfd, &cmd);
    }
    else if (eq(cmd.verb, "STOR") == 1) {
        handleStore(connfd, &cmd);
    }
    else {
        printf("No match for [%d], [%s]\n", nbytes, argStr);
    }
    // sprintf()
    // printf("Command: [%s] [%s]\n", cmd.verb, cmd.arg);
}


int serve(int connfd) {
    sendStr(connfd, "220 Hello\r\n");

    char pwd[258] = {0};
    getcwd(pwd, 256);
    updateWd(&wd, pwd);
    // printf("%s, \n", p);
    // printf("%s, \n", pwd);

    // printf("send str\n");
    // close(connfd);
    // return 0;
    char sentence[BUF_LEN + 1];
    while (1) {
        int recvBytes = recv(connfd, sentence, BUF_LEN, 0);
        if (recvBytes < 0) {
            error("recv fails");
            close(connfd);
            return -1;
        }
        else if (recvBytes == 0) {
            info("recv 0 bytes, quit");
            close(connfd);
            return 0;
        }
        else {
            sentence[recvBytes] = '\0';
            // printf("%d\n", recvBytes);
            // printf("%s\n", sentence);
            // for (int i = 0; i < recvBytes; i++) {
            //     printf("[%c],[%d]\n", sentence[i], sentence[i]);
            // }
            
            int res = dispatch(connfd, sentence, recvBytes);
            // printf("\n");
            memset(sentence, 0, BUF_LEN * sizeof(char));

            if (res == QUIT_CODE)
                break;
        }
        // printf(sentence);
    }
}


int mainproc() {
    int listenfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenfd == -1) {
        error("socket fails");
    }
    int on = 1;
    int ret = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));

    struct sockaddr_in serverAddr = buildSockAddr(NULL, PORT);
    int a = bind(listenfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    int b = listen(listenfd, 20);

    printf("%d%d%d\n", a, ret, b);

    int connfd;
	struct sockaddr_in clientAddr;
    socklen_t clientLength;
    printf("reach while \n");
    while (1) {
        connfd = accept(listenfd, NULL, NULL);
        // connfd = accept(listenfd, (struct sockaddr*) &clientAddr, &clientLength);
        if (connfd == -1) {
            printf("conn -1\n");
            continue;
        }
        else {
            pid = fork();
            if (pid < 0) {
                printf("[ERROR] fork fails");
            }
            else if (pid == 0) {
                close(listenfd);
                serve(connfd);
                close(connfd);
                return 0;
            }
            close(connfd);
        }

        printf("Received %d\n", clientAddr.sin_port);

        // close(listenfd);
        // serve(connfd);
        close(connfd);
    }

        // return 0;

    close(listenfd);

    //  while (1) {
    //     if ((connfd = accept(listenfd, NULL, NULL)) == -1) {
    //         printf("Error accept(): %s(%d)\n", strerror(errno), errno);
    //         continue;
    //     }else{
	// 		//connection accepted
	// 		int pid = fork();
	// 		if(pid < 0){
	// 			printf("Error fork()");
	// 		}else if(pid == 0){
	// 			close(listenfd);
	// 			serve_client(connfd);
	// 			close(connfd);
	// 			return 0;
	// 		}
	// 		close(connfd);
	// 	}
    //     close(connfd);
    // }
    // close(listenfd);

    return 0;
}





int main(int argc, char **argv) {
    srand((unsigned)time(NULL));
    mainproc();
    // printf("hello");
}

