#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>

#include <unistd.h>
#include <errno.h>

#include <ctype.h>
#include <string.h>
#include <memory.h>
#include <stdio.h>

#include <arpa/inet.h>

#include "operation.h"


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
        // printf("asdsadasdasd%d, %s", pres->hasMsg, reply);
        sprintf(reply, "%d\r\n", pres->status);
    }
    printf("[DEBUG] Send response [%d: %s]\n", pres->status, pres->msg);
    sendStr(sockfd, reply);
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
    printf("asdasd[%s][%s]\n", cmd.verb, cmd.arg);
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
