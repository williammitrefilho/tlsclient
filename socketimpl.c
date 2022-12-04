#include <errno.h>
#include <stdio.h>
#include <socketimpl.h>

int findHostAddr(char *addrstr, char *port){
	
	struct addrinfo *addr_info, hint;
	hint.ai_family = AF_INET;
	hint.ai_socktype = 0;
	hint.ai_protocol = IPPROTO_TCP;
	hint.ai_next = 0;
	hint.ai_canonname = 0;
	hint.ai_addrlen = 0;
	hint.ai_addr = 0;
	hint.ai_flags = 0;
	
	int s = 0;
	int r = getaddrinfo(addrstr, "", &hint, &addr_info);
	printf("return: %d\n", r);
	if(r) {
		printf("erro findHostAddr:%s\n", gai_strerror(r));
	}
	else {
		int r = getaddrinfo(addrstr, port, &hint, &addr_info);
		if(r){
			printf("erro:%s\n", gai_strerror(r));
		} else {
			s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			r = connect(s, addr_info->ai_addr, addr_info->ai_addrlen);
			if(r){
				printf("erro connect:%d\n", r);
				return 0;
			} else {
				freeaddrinfo(addr_info);
				return s;
			}
		}
		freeaddrinfo(addr_info);
	}
	return 0;
}

int socketStartup(){
	// int r;
	#ifdef _WIN32
	WSADATA wsaData;
	DWORD wVersion = MAKEWORD(2, 2);
	WSAStartup(wVersion, &wsaData);
	#endif
	return 0;
}

void socketCleanup(){
	
	#ifdef _WIN32
	WSACleanup();
	#endif
}

#ifndef _WIN32
int closesocket(int s){
	close(s);
	return 0;
}
#endif
