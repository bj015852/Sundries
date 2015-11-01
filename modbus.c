#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define MAX_COMMAND_LEN (int)200
#define SERVERPORT (int)502
#define MAXDATASIZE (int)200
#define MAX_CMD_NUM (int)20
#define SERVER_IP "172.18.15.22"
#define DATA "this is a client message!"
#define MAX(a,b) (a>b)?(a):(b)

typedef struct {
    unsigned char reserve[5];
    unsigned char len;
    unsigned char unit;
    unsigned char fc;
    unsigned short address;
} MODBUS_TCP_SEND_HEADER;

typedef struct {
    unsigned char reserve[5];
    unsigned char len;
    unsigned char unit;
    unsigned char fc;
} MODBUS_TCP_HEADER;

typedef struct {
    unsigned char reserve[5];
    unsigned char len;
    unsigned char unit;
    unsigned char fc;
    unsigned char bytecount;
} MODBUS_TCP_RECV_READ_HEADER;

typedef struct {
    unsigned char reserve[5];
    unsigned char len;
    unsigned char unit;
    unsigned char fc;
    unsigned short add;
} MODBUS_TCP_RECV_WRI_HEADER;

typedef struct {
    unsigned char reserve[5];
    unsigned char len;
    unsigned char unit;
    unsigned char errorcode;
    unsigned char exceptioncode;
} MODBUS_TCP_ERR_HEADER;

int sockfd;
int nUnConnectNum = 0;/*未接收到数据的次数*/

void init_modbus_tcp(void);
int cmd_parse(char *buf, char *argv[]);
int parse_modbus_cmd(int argc, char *argv[]);
int read_coil_input(int argc, char *argv[]);
int read_descrete_input(int argc, char *argv[]);
int read_holding_input(int argc, char *argv[]);
int read_input_register(int argc, char *argv[]);
int write_coil(int argc, char *argv[]);
int write_holding_register(int argc, char *argv[]);
int do_modbus_cmd(unsigned char *pCmdHex, int CmdLen);
void send_modbus_cmd(unsigned char *pSendData, int SendSize);
void display_server_cmd(unsigned char *pRecvBuf, int nRecvBytes);
void print_data(unsigned char *pData, int nFc);
void close_modbus_tcp(void);
void disconnect_solve(void);
unsigned int char2hex(unsigned char c);
unsigned char *string2hex(unsigned char * pString, int StrSize);
unsigned char hex2charhigh(unsigned char c);
unsigned char hex2charlow(unsigned char c);
unsigned char *hex2string(unsigned char * pHex, int HexSize);
unsigned char *hex2string(unsigned char * pHex, int HexSize);
void print_Modbus_usage(void);
void send_heart_cmd(unsigned char *pSendData, int SendSize);

/*初始化套接字建立连接*/
void init_modbus_tcp()
{
    struct sockaddr_in serv_addr;
    char cIP[20];
    if ((sockfd = socket(AF_INET,SOCK_STREAM, 0)) == -1){
        perror("socket error!");
        exit(1);
    }
    printf("Please input the Modbus TCP Server IP, input \"quit\" to exit: \n");
    fgets(cIP, sizeof(cIP), stdin);
    if (strcmp(cIP, "quit") == 0){
        exit(0);
    }
    bzero(&serv_addr,sizeof(serv_addr));
    serv_addr.sin_family= AF_INET;
    serv_addr.sin_port = htons(SERVERPORT);
    serv_addr.sin_addr.s_addr=inet_addr(cIP);
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(struct sockaddr))==-1){
        perror("connect error");
        exit(1);
    }
    printf("Connected!");
    if (!fork()){
        char cCommand[] = {"000000000006010300630001"};
        unsigned char *cCmdHex = NULL;
        cCmdHex = string2hex((unsigned char *)cCommand, strlen(cCommand));
        while (1){
            //cCmdHex = string2hex((unsigned char *)cCommand, strlen(cCommand));
            //send_heart_cmd(cCmdHex, strlen(cCommand)/2);
            sleep(5);
            if (getppid() == 1){
                free(cCmdHex);
                cCmdHex = NULL;
                printf("end heartbeat fork\n");
                exit(0);
            }
        }
    }
}

/*发送modbus命令给模拟器，再接收返回的命令*/
void send_heart_cmd(unsigned char *pSendData, int SendSize)
{
    int recvbytes;
    char buf[MAXDATASIZE];
    fd_set rSet;
    struct timeval tm;
    int nReady = 0;

    FD_ZERO(&rSet);
    FD_SET(sockfd, &rSet);
    tm.tv_sec = 2;
    tm.tv_usec = 0;

    write(sockfd,pSendData,SendSize);
    nReady = select(sockfd + 1, &rSet, NULL, NULL, &tm);
    if (nReady < 0){
        perror("Select Error");
    }
    else if (nReady == 0){
        printf("Read Timeout. Nothing has been received.\n");
    }
    else{
        if (FD_ISSET(sockfd, &rSet)){
            recvbytes = recv(sockfd,buf,MAXDATASIZE, 0);
            if (recvbytes == -1){
                perror("recv error!");
                exit(1);
            }
            else if (recvbytes == 0){
                printf("Sever has been disconnected...\n");
                exit(0);
            }
            else{
                //display_server_cmd((unsigned char*)buf, recvbytes);
                printf("hahah\n");
            }
        }
    }
}

/*处理输入的命令，将其存为字符串数组*/
int cmd_parse(char *buf, char *argv[]) {
    if ((buf == NULL)) {
        return 0;
    }
    int argc = 0;
    int state = 0;
    while (*buf != '\0') {
        if ((*buf != ' ') && (state == 0)) {
            argv[argc++] = buf;
            state = 1;
        }
        if ((*buf == ' ') && (state == 1)) {
            *buf = '\0';
            state = 0;
        }
        buf++;
    }
    return argc;
}

/*解析输入的modbus命令*/
int parse_modbus_cmd(int argc, char *argv[])
{
    if (strcmp(argv[0], "quit") == 0) {
        close_modbus_tcp();
        exit(0);
    }
    if ((argc < 3) || (argv == NULL)) {
        print_Modbus_usage();
        return -1;
    }
    else if (strcmp(argv[0], "rc") == 0) {
        read_coil_input(argc, argv);
    }
    else if (strcmp(argv[0], "rd") == 0) {
        read_descrete_input(argc, argv);
    }
    else if (strcmp(argv[0], "rh") == 0) {
        read_holding_input(argc, argv);
    }
    else if (strcmp(argv[0], "ri") == 0) {
        read_input_register(argc, argv);
    }
    else if (strcmp(argv[0], "wc") == 0) {
        write_coil(argc, argv);
    }
    else if (strcmp(argv[0], "wh") == 0) {
        write_holding_register(argc, argv);
    }
    else {
        print_Modbus_usage();
    }
    return 0;
}

/*读取保持寄存器状态, fc=3*/
int read_holding_input(int argc, char *argv[])
{
    char crhCommand[MAX_COMMAND_LEN] = {0};
    int nAddrLen;
    int nCountLen;
    unsigned char *cCmdHex = NULL;
    nAddrLen = strlen(argv[1]);
    nCountLen = strlen(argv[2]);
    int i = 0;
    for (i = 0; i<10; i++){
        crhCommand[i] = '0';
    }
    crhCommand[10] = '0';
    crhCommand[11] = '6';
    crhCommand[12] = '0';
    crhCommand[13] = '1';
    crhCommand[14] = '0';
    crhCommand[15] = '3';
    for (i = 0; i<nAddrLen; i++){
        crhCommand[19-i] = argv[1][nAddrLen-i-1];
    }
    for (i = nAddrLen; i < 4; i++){
        crhCommand[19-i] = '0';
    }
    for (i = 0; i<nCountLen; i++){
        crhCommand[23-i] = argv[2][nCountLen-i-1];
    }
    for (i = nCountLen; i < 4; i++){
        crhCommand[23-i] = '0';
    }
    printf("Sending: %s\n", crhCommand);
    cCmdHex = string2hex((unsigned char *)crhCommand, strlen(crhCommand));
    do_modbus_cmd(cCmdHex, strlen(crhCommand)/2);
    return argc;
}

/*读取线圈状态, fc=1*/
int read_coil_input(int argc, char *argv[])
{
    char crhCommand[MAX_COMMAND_LEN] = {0};
    int nAddrLen;
    int nCountLen;
    unsigned char *cCmdHex = NULL;
    nAddrLen = strlen(argv[1]);
    nCountLen = strlen(argv[2]);
    int i = 0;
    for (i = 0; i<10; i++){
        crhCommand[i] = '0';
    }
    crhCommand[10] = '0';
    crhCommand[11] = '6';
    crhCommand[12] = '0';
    crhCommand[13] = '1';
    crhCommand[14] = '0';
    crhCommand[15] = '1';
    for (i = 0; i<nAddrLen; i++){
        crhCommand[19-i] = argv[1][nAddrLen-i-1];
    }
    for (i = nAddrLen; i < 4; i++){
        crhCommand[19-i] = '0';
    }
    for (i = 0; i<nCountLen; i++){
        crhCommand[23-i] = argv[2][nCountLen-i-1];
    }
    for (i = nCountLen; i < 4; i++){
        crhCommand[23-i] = '0';
    }
    printf("Sending: %s\n", crhCommand);
    cCmdHex = string2hex((unsigned char *)crhCommand, strlen(crhCommand));
    do_modbus_cmd(cCmdHex, strlen(crhCommand)/2);
    return argc;
}

/*读取离散输入寄存器状态, fc=2*/
int read_descrete_input(int argc, char *argv[])
{
    char crhCommand[MAX_COMMAND_LEN] = {0};
    int nAddrLen;
    int nCountLen;
    unsigned char *cCmdHex = NULL;
    nAddrLen = strlen(argv[1]);
    nCountLen = strlen(argv[2]);
    int i = 0;
    for (i = 0; i<10; i++){
        crhCommand[i] = '0';
    }
    crhCommand[10] = '0';
    crhCommand[11] = '6';
    crhCommand[12] = '0';
    crhCommand[13] = '1';
    crhCommand[14] = '0';
    crhCommand[15] = '2';
    for (i = 0; i<nAddrLen; i++){
        crhCommand[19-i] = argv[1][nAddrLen-i-1];
    }
    for (i = nAddrLen; i < 4; i++){
        crhCommand[19-i] = '0';
    }
    for (i = 0; i<nCountLen; i++){
        crhCommand[23-i] = argv[2][nCountLen-i-1];
    }
    for (i = nCountLen; i < 4; i++){
        crhCommand[23-i] = '0';
    }
    printf("Sending: %s\n", crhCommand);
    cCmdHex = string2hex((unsigned char *)crhCommand, strlen(crhCommand));
    do_modbus_cmd(cCmdHex, strlen(crhCommand)/2);
    return argc;
}

/*读取输入寄存器状态, fc=4*/
int read_input_register(int argc, char *argv[])
{
    char crhCommand[MAX_COMMAND_LEN] = {0};
    int nAddrLen;
    int nCountLen;
    unsigned char *cCmdHex = NULL;
    nAddrLen = strlen(argv[1]);
    nCountLen = strlen(argv[2]);
    int i = 0;
    for (i = 0; i<10; i++){
        crhCommand[i] = '0';
    }
    crhCommand[10] = '0';
    crhCommand[11] = '6';
    crhCommand[12] = '0';
    crhCommand[13] = '1';
    crhCommand[14] = '0';
    crhCommand[15] = '4';
    for (i = 0; i<nAddrLen; i++){
        crhCommand[19-i] = argv[1][nAddrLen-i-1];
    }
    for (i = nAddrLen; i < 4; i++){
        crhCommand[19-i] = '0';
    }
    for (i = 0; i<nCountLen; i++){
        crhCommand[23-i] = argv[2][nCountLen-i-1];
    }
    for (i = nCountLen; i < 4; i++){
        crhCommand[23-i] = '0';
    }
    printf("Sending: %s\n", crhCommand);
    cCmdHex = string2hex((unsigned char *)crhCommand, strlen(crhCommand));
    do_modbus_cmd(cCmdHex, strlen(crhCommand)/2);
    return argc;
}

/*写入保持寄存器, fc=6*/
int write_holding_register(int argc, char *argv[])
{
    char crhCommand[MAX_COMMAND_LEN] = {0};
    int nAddrLen;
    int nCountLen;
    unsigned char *cCmdHex = NULL;
    nAddrLen = strlen(argv[1]);
    nCountLen = strlen(argv[2]);
    int i = 0;
    for (i = 0; i<10; i++){
        crhCommand[i] = '0';
    }
    crhCommand[10] = '0';
    crhCommand[11] = '6';
    crhCommand[12] = '0';
    crhCommand[13] = '1';
    crhCommand[14] = '0';
    crhCommand[15] = '6';
    for (i = 0; i<nAddrLen; i++){
        crhCommand[19-i] = argv[1][nAddrLen-i-1];
    }
    for (i = nAddrLen; i < 4; i++){
        crhCommand[19-i] = '0';
    }
    for (i = 0; i<nCountLen; i++){
        crhCommand[23-i] = argv[2][nCountLen-i-1];
    }
    for (i = nCountLen; i < 4; i++){
        crhCommand[23-i] = '0';
    }
    printf("Sending: %s\n", crhCommand);
    cCmdHex = string2hex((unsigned char *)crhCommand, strlen(crhCommand));
    do_modbus_cmd(cCmdHex, strlen(crhCommand)/2);
    return argc;
}

/*写入线圈, fc=5*/
int write_coil(int argc, char *argv[])
{
    char crhCommand[MAX_COMMAND_LEN] = {0};
    int nAddrLen;
    int nCountLen;
    unsigned char *cCmdHex = NULL;
    nAddrLen = strlen(argv[1]);
    nCountLen = strlen(argv[2]);
    int i = 0;
    for (i = 0; i<10; i++){
        crhCommand[i] = '0';
    }
    crhCommand[10] = '0';
    crhCommand[11] = '6';
    crhCommand[12] = '0';
    crhCommand[13] = '1';
    crhCommand[14] = '0';
    crhCommand[15] = '5';
    for (i = 0; i<nAddrLen; i++){
        crhCommand[19-i] = argv[1][nAddrLen-i-1];
    }
    for (i = nAddrLen; i < 4; i++){
        crhCommand[19-i] = '0';
    }
    for (i = 0; i<nCountLen; i++){
        crhCommand[23-i] = argv[2][nCountLen-i-1];
    }
    for (i = nCountLen; i < 4; i++){
        crhCommand[23-i] = '0';
    }
    printf("Sending: %s\n", crhCommand);
    cCmdHex = string2hex((unsigned char *)crhCommand, strlen(crhCommand));
    do_modbus_cmd(cCmdHex, strlen(crhCommand)/2);
    return argc;
}

/*按照解析好的输入命令进行处理*/
int do_modbus_cmd(unsigned char *pCmdHex, int CmdLen)
{
    if (pCmdHex[0]==0 && CmdLen == 1)
    {
        close_modbus_tcp();
        exit(0);
    }
    else
    {
        send_modbus_cmd(pCmdHex, CmdLen);
    }
    return 0;
}

/*发送modbus命令给模拟器，再接收返回的命令*/
void send_modbus_cmd(unsigned char *pSendData, int SendSize)
{
    int recvbytes;
    char buf[MAXDATASIZE];
    fd_set rSet;
    struct timeval tm;
    int nReady = 0;

    FD_ZERO(&rSet);
    FD_SET(sockfd, &rSet);
    tm.tv_sec = 2;
    tm.tv_usec = 0;

    write(sockfd,pSendData,SendSize);
    nReady = select(sockfd + 1, &rSet, NULL, NULL, &tm);
    if (nReady < 0){
        perror("Select Error\n");
    }
    else if (nReady == 0){
        printf("Read Timeout. Nothing has been received.\n");
        nUnConnectNum++;
    }
    else{
        if (FD_ISSET(sockfd, &rSet)){
            recvbytes = recv(sockfd,buf,MAXDATASIZE, 0);
            if (recvbytes == -1){
                perror("recv error!");
                exit(1);
            }
            else if (recvbytes == 0){
                printf("Sever has been disconnected...\n");
                exit(0);
            }
            else{
                nUnConnectNum--;
                nUnConnectNum = MAX(0, nUnConnectNum);
                display_server_cmd((unsigned char*)buf, recvbytes);
            }
        }
    }
    free(pSendData);
    pSendData = NULL;
    /*多次未收到返回数据*/
    if (nUnConnectNum >= 3){
        disconnect_solve();
    }
}

/*将模拟器返回的命令分类显示*/
void display_server_cmd(unsigned char *pRecvBuf, int nRecvBytes)
{
    unsigned char *pRecvData = NULL;
    MODBUS_TCP_HEADER ModbusHeader;
    unsigned short bytecount = 0;
    pRecvData = hex2string((unsigned char *)pRecvBuf, nRecvBytes);
    pRecvData[nRecvBytes*2] = '\0';
    printf("Received data from Modsim: %s\n", pRecvData);
    printf("data size: %d\n", nRecvBytes);

    memset(&ModbusHeader, 0, sizeof(ModbusHeader));
    memcpy(&ModbusHeader, pRecvBuf, sizeof(ModbusHeader));
    printf("Device ID: %d\n", ModbusHeader.unit);
    /*功能码为1,2,3,4*/
    if (ModbusHeader.fc==1 || ModbusHeader.fc==2 || ModbusHeader.fc==3 || ModbusHeader.fc==4){
        MODBUS_TCP_RECV_READ_HEADER ModbusReadHeader;
        memset(&ModbusReadHeader, 0, sizeof(ModbusReadHeader));
        memcpy(&ModbusReadHeader, pRecvBuf, sizeof(ModbusReadHeader));
        bytecount = ModbusReadHeader.bytecount;
        printf("Function Code: %d\n", ModbusHeader.fc);
        printf("Byte Count: %d\n", bytecount);
        unsigned char *Data = pRecvData + 2*sizeof(MODBUS_TCP_RECV_READ_HEADER);
        print_data(Data, ModbusReadHeader.fc);
        if ((strlen((char *)Data) % 8) == 0){
            unsigned int nData;
            char *hexData = (char *)pRecvBuf + sizeof(MODBUS_TCP_RECV_READ_HEADER);
            memcpy(&nData, hexData, 4);
            unsigned int nTempData;
            nTempData = nData & 0xffff;
            nData = (nData >> 16);
            nData = nData | (nTempData << 16);
            nData = ntohl(nData);
            float fData;
            memcpy(&fData,&nData,4);
            printf("    (int): %d\n", nData);
            printf("  (float): %f\n", fData);
        }
    }
    /*功能码为5,6*/
    else if (ModbusHeader.fc==5 || ModbusHeader.fc==6){
        MODBUS_TCP_RECV_WRI_HEADER ModbusWriHeader;
        memset(&ModbusWriHeader, 0, sizeof(ModbusWriHeader));
        memcpy(&ModbusWriHeader, pRecvBuf, sizeof(ModbusWriHeader));
        bytecount = ModbusWriHeader.add;
        printf("Function Code: %d\n", ModbusHeader.fc);
        printf("Address: %d\n", bytecount);
        unsigned char *Data = pRecvData + 2*sizeof(MODBUS_TCP_RECV_WRI_HEADER);
        //printf("Data(Hex): %s\n", Data);
        print_data(Data, ModbusWriHeader.fc);
    }
    /*错误功能码*/
    else if ((ModbusHeader.fc & 0x80) == 0x80){
        MODBUS_TCP_ERR_HEADER ModbusErrHeader;
        memset(&ModbusErrHeader, 0, sizeof(ModbusErrHeader));
        memcpy(&ModbusErrHeader, pRecvBuf, sizeof(ModbusErrHeader));
        printf("There an Exception in Function Code %d\n", ModbusErrHeader.errorcode & 0x0f);/*显示错误的功能码*/
        printf("The Exception Code is: %d. Reason: ", ModbusErrHeader.exceptioncode);
        switch(ModbusErrHeader.exceptioncode){
        case 1: printf("Illegal Function\n"); break;
        case 2: printf("Illegal Data Address\n"); break;
        case 3: printf("Illegal Data Value\n"); break;
        default: printf("Unkown\n"); break;
        }
    }
    else {
        printf("Function Code: %d\n", ModbusHeader.fc);
    }
    free(pRecvData);
    pRecvData = NULL;
}

/*显示Modbus的Data字段内容*/
void print_data(unsigned char *pData, int nFc)
{
    int nDataLen = strlen((char *)pData);
    int nInterval = 4;
    if (nFc==1 || nFc==2){   /*根据功能码决定多少个数进行间隔\0*/
        nInterval = 2;
    }
    else{
        nInterval = 4;
    }
    unsigned char *pPrintBuf = (unsigned char*)malloc(nDataLen + nDataLen/nInterval);
    if (!pPrintBuf){
        printf("Malloc Error\n");
    }
    else {                                   /*每隔nInterval个数字添加一个空格*/
        int i = 0;
        int nloca = 0;
        for (i=0, nloca=0; i<(nDataLen/nInterval); i++, nloca++){
            memcpy(pPrintBuf + i*nInterval + nloca, pData + i*nInterval, nInterval);
            pPrintBuf[(i+1)*nInterval+nloca] =' ';
        }
    }
    pPrintBuf[nDataLen + nDataLen/nInterval-1]='\0';    /*防止越界将最后的空格变成\0*/
    printf("Data(Hex): %s\n", pPrintBuf);

    free(pPrintBuf);
    pPrintBuf = NULL;
}

/*关闭套接字*/
void close_modbus_tcp()
{
    close(sockfd);
}

/*断线处理，关闭tcp连接，重新链接*/
void disconnect_solve()
{
    close_modbus_tcp();
    printf("\nNetwork unstable, please try to reconnect the server\n");
    sleep(1);
    init_modbus_tcp();
}

/**char to hex **/
unsigned int char2hex(unsigned char c)
{
    if ('0'<=c && '9' >= c){
        return c-'0';
    }
    if ('A' <= c && 'F' >= c){
        return c-'A'+10;
    }
    if ('a'<=c && 'f' >= c){
        return c-'a'+10;
    }
    return -1;
}

/**string to hex **/
unsigned char *string2hex(unsigned char * pString, int StrSize)
{
    unsigned char *pHex = (unsigned char*) malloc (StrSize/2);
    if (!pHex){
        printf("Malloc Error\n");
    }
    else {
        int i = 0;
        int j = 0;
        for (i=0,j=0; i<StrSize; j++){
            pHex[j]=char2hex(pString[i])*16+char2hex(pString[i+1]);
            i=i+2;
        }
    }
    return pHex;
}

/**hex to char high **/
unsigned char hex2charhigh(unsigned char c)
{
    unsigned int chigh=0;
    unsigned int clow=0;
    chigh = c/16;
    clow = c - chigh*16;
    if (9 >= chigh){
        chigh=chigh+'0';
    }
    if (10 <= chigh && 15 >= chigh){
        chigh=chigh+'a'-10;
    }
    if (9 >= clow){
        clow=clow+'0';
    }
    if (10 <= clow && 15 >= clow){
        clow=clow+'a'-10;
    }
    return chigh;
}

/**hex to char low**/
unsigned char hex2charlow(unsigned char c)
{
    unsigned int chigh=0;
    unsigned int clow=0;
    chigh = c/16;
    clow = c - chigh*16;
    if (9 >= chigh){
        chigh=chigh+'0';
    }
    if (10 <= chigh && 15 >= chigh){
        chigh=chigh+'a'-10;
    }
    if (9 >= clow){
        clow=clow+'0';
    }
    if (10 <= clow && 15 >= clow){
        clow=clow+'a'-10;
    }
    return clow;
}

unsigned char *hex2string(unsigned char * pHex, int HexSize)
{
    unsigned char *pString = (unsigned char*) malloc (HexSize*2 + 1);
    if(!pString){
        printf("Maclloc Error.\n");
    }
    else{
        int i = 0;
        int j = 0;
        for (i=0,j=0;i<HexSize;i++){
            pString[j]=hex2charhigh(pHex[i]);
            pString[j+1]=hex2charlow(pHex[i]);
            j=j+2;
        }
    }
    return pString;
}

/*打印提示信息*/
void print_Modbus_usage(void)
{
    printf("*********************Usage**********************\n");
    printf("rc + unit start_address + count  ---read coil\n");
    printf("rd + unit start_address + count  ---read discrete inputs\n");
    printf("rh + unit start_address + count  ---read holding register\n");
    printf("ri + unit start_address + count  ---read input register\n");
    printf("wc + unit start_address + count  ---write coil\n");
    printf("wh + unit start_address + count  ---write holding register\n");
    printf("quit  ---exit\n");
    printf("*************************************************\n\n");
}

int main(void)
{
    char cCommand[MAX_COMMAND_LEN] = {0};
    int argc_cmd;
    char *argv_cmd[MAX_CMD_NUM];
    unsigned char *cCmdHex = NULL;
    nUnConnectNum = 0;
    printf("Welcome:\n");
    init_modbus_tcp();
    print_Modbus_usage();
    while (1)
    {
        printf("Please input the Modbus Commond, input \"quit\" to exit:\n");
        fgets(cCommand, sizeof(cCommand), stdin);
        cCommand[strlen(cCommand) - 1] = '\0';
        argc_cmd = cmd_parse(cCommand, argv_cmd);
        if (argc_cmd == 0){/*Without this judgement, there will be a stack overflow in the next if expression*/
            continue;
        }
        if (strcmp(argv_cmd[0], "h") == 0 && argc_cmd==1){ /*输入h的话，直接输入modbus报文码*/
            printf("input Modbus packet:\n");
            fgets(cCommand, sizeof(cCommand), stdin);
            cCommand[strlen(cCommand) - 1] = '\0';
            cCmdHex = string2hex((unsigned char *)cCommand, strlen(cCommand));
            printf("Now sending: %s\n", cCommand);
            do_modbus_cmd(cCmdHex, strlen(cCommand)/2);
            continue;
        }
        parse_modbus_cmd(argc_cmd, argv_cmd);/*正常流程*/
    }
    return 0;
}
