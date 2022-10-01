# tlsclient
How small can a TLS/crypto library be?

## 1. Introduction
Some time ago I was developing a web app for my own business, that should be fully web-based, but still communicate with peripherals on the client side.

## 2. Overview
The client is written entirely in **C**. Two of the most common cipher suites for TLS 1.2 are implemented, namely **TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA** and **TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA**.
TLS 1.3's **TLS_AES_128_GCM_SHA256** and **TLS_AES_256_GCM_SHA384** are also written in code, but have not been tested.

The client supports full TLS handshakes, exchange of application data, and session renegotiation.

## 3. Building
Install **mingw**, than run ```build.bat``` on the command prompt.

## 4. Testing
```C
#include <tlsbase.h>
#include <string.h>
int main(int argc, char *argv[]){
	
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	TLSClient *client = tls_connect("www.google.com", "443"); // Initiate and connect to remote server
	
	if(client){
		if(tls_handshake(client, "www.google.com", "443")){ // perform the TLS handshake
			
			printf("erro handshake\n");
		}
		else{
			
			unsigned char request[] = "GET / HTTP/1.1\r\nHost:www.google.com\r\n\r\n";
			tls_send_application_data(client, request, strlen(request)); // send application data
			tls_receive_application_data(client);
			printf(client->application_data);
		}
		tls_free_client(client);
	}
	
	WSACleanup();
	return 0;
}
```

## 5. Why??
One possible solution seemed to be writing a browser extension, but then I would have to write one for each browser that would support my app. I wanted all of them to support it, like everybody else. Besides, I stumbled upon one announcement from Google that they would be removing support for native messaging in the extensions.

The other was developing a native app for communicating with the server directly, basically an HTTPS client. But at first that seemed to involve importing OpenSSL (65 megabytes of code) into my project. By that time, I had a very unreliable 3G/4G connection, and a download that size was likely to fail.

So I thought about importing just the parts of OpenSSL I would need to barely establish the HTTPS connection.

But then it occurred to me that I was perhaps too far from home. What if, by trying to develop such an app, I was taking on more than I could handle? A suggestion I sometimes accept from others, but never from my own self.

So I decided to drop OpenSSL, embark on a journey to IETF and NIST, and write my TLS client from scratch.

But, in the end, it worked, and is 0,35% the size of OpenSSL code.