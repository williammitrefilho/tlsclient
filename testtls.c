//William Mitre Filho - 2022
//Testando!
#include <tlsbase.h>
#include <string.h>
int main(int argc, char *argv[]){
	
	init_logger();
	socketStartup();
	TLSClient *client = tls_connect("www.google.com", "443"); // Initiate and connect to remote server
	
	if(client){
		if(tls_handshake(client, "www.google.com", "443")){ // perform the TLS handshake
			
			printf("%s erro handshake. transcript:\n", logerr());
			printbhex(client->transcript, client->transcript_len);printf("\n");
		}
		else{
			
			unsigned char request[] = "GET / HTTP/1.1\r\nHost:www.google.com\r\n\r\n";
			tls_send_application_data(client, request, strlen(request)); // send application data
			tls_receive_application_data(client);
			printf("%s\n", client->application_data);
		}
		tls_free_client(client);
	}
	
	socketCleanup();
	clean_logger_up();
	return 0;
}
