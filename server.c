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

#include "operation.h"

char username[32] = {0};
char password[32] = {0};
char pwd[258] = {0};

int channel = CHANNEL_BLOCK;

// Address* pPort = NULL;
SockPort sp;


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

int handlePwd(int connfd, Command* pcmd) {
    Response res;
    res.status = 257;
    res.hasMsg = 1;
    strcpy(res.msg, pwd);
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
    int port = rand() % (65536 - 20000) + 20000;
    int p1 = port / 256;
    int p2 = port % 256;
    
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

    int trfd = 0;
    
    switch (channel) {
        case CHANNEL_PORT:
            if (connectTo(&sp) != 0) {
                return 1;
            }
            trfd = sp.connfd;
            break;
        case CHANNEL_PASV:
            
            trfd = accept(sp.connfd, NULL, NULL);
            // printf("asd?%d\n", trfd);
            break;
        default:
            break;
    }

    // send response for start
    Response res;
    res.status = 150;
    res.hasMsg = 0;
    sendRes(connfd, &res);

    // tranfering list information
    DIR *dirp;
    struct dirent *dp;
    dirp = opendir(pwd); //打开目录指针
    char buf[256] = {0};
    
    while ((dp = readdir(dirp)) != NULL) { //通过目录指针读目录
        sprintf(buf, ">-- %s\r\n", dp->d_name);
        sendStr(trfd, buf);
        printf("%s", buf);
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
    else if (eq(cmd.verb, "PWD") == 1) {
        handlePwd(connfd, &cmd);
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
    else {
        printf("No match for [%d], [%s]\n", nbytes, argStr);
    }
    // sprintf()
    // printf("Command: [%s] [%s]\n", cmd.verb, cmd.arg);
}


int serve(int connfd) {
    sendStr(connfd, "220 Hello\r\n");

    getcwd(pwd, 256);
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

        printf("Received %d\n", clientAddr.sin_port);

        close(listenfd);
        serve(connfd);
        close(connfd);
        printf("close\n");
        // int pid = fork();
        // if (pid == 0) {
        //     close(listenfd);
        //     serve(connfd);
        //     close(connfd);
        //     printf("close\n");
        // }
        // close(connfd);
        // close(listenfd);
        return 0;
    }

    close(listenfd);
    return 0;
}





int main(int argc, char **argv) {
    srand((unsigned)time(NULL));
    mainproc();
    // printf("hello");
}

