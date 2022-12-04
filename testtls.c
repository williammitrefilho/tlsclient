//William Mitre Filho - 2022
//Testando!
#include <tlsbase.h>
#include <string.h>
int main(int argc, char *argv[]){
	
	socketStartup();
	unsigned char *hostname, default_hostname[] = "www.google.com";
	if(argc < 2)
		hostname = default_hostname;
	else
		hostname = argv[1];

	TLSClient *client = tls_connect(hostname , "443"); // Initiate and connect to remote server
	
	if(client){
		if(tls_handshake(client, hostname, "443")){ // perform the TLS handshake
			
			printf("%s erro handshake\n");
		}
		else{
			
			unsigned char request[512];
		       	sprintf(request, "GET / HTTP/1.1\r\nHost:%s\r\n\r\n", hostname);
			tls_send_application_data(client, request, strlen(request)); // send application data
			tls_receive_application_data(client);
			printf("%s\n", client->application_data);
		}
		tls_free_client(client);
	}
	
	socketCleanup();
	return 0;
}
