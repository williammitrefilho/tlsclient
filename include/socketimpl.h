#ifdef _WIN32

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#else
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#endif

#ifndef SOCKETIMPL_H

#define SOCKETIMPL_H

int findHostAddr(char *addrstr, char *port);
int socketStartup();
void socketCleanup();

#ifndef _WIN32
int closesocket(int s);
#endif

#endif

