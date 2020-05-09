#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <math.h>
#include <termios.h>
#include <ctype.h>
#include <unistd.h>  

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "../ca_client" 

#define BUFF_SIZE 2000

struct tls_header {
	unsigned short int tlsh_len;
};

struct cred_header {
	unsigned short int user_len;
	unsigned short int pwd_len;
	unsigned short int pckt_len;
};

int createTunDevice() {
	int tunfd;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  
	tunfd = open("/dev/net/tun", O_RDWR);
	ioctl(tunfd, TUNSETIFF, &ifr);       
	return tunfd;
}

void tunSelected(int tunfd, SSL* ssl){
	int length, len, err;
	char buff[BUFF_SIZE];
	char buffer[4];
	memset(buffer, 0, 4);
	struct tls_header *tls = (struct tls_header *) buffer; 
	printf("Got a packet from TUN\n");
	bzero(buff, BUFF_SIZE);
	length = read(tunfd, buff, BUFF_SIZE);
    // Sending the Length of the packet and then the packet itself.
	tls->tlsh_len = htons(length);
	err = SSL_write(ssl, tls, sizeof(struct tls_header)); CHK_SSL(err);
	err = SSL_write(ssl, buff, length); CHK_SSL(err); 
}

void socketSelected (int tunfd, SSL* ssl){
	int  i, len, data_length, length, err, total;
	char buff[BUFF_SIZE];
	bzero(buff, BUFF_SIZE);
	char *ptr = (char *)buff;
	char buffer[4];
	memset(buffer, 0, 4);
	struct tls_header *tls = (struct tls_header *) buffer;
	printf("Got a packet from the tunnel\n");
    // Reading the Packet length and then the packet
	err = SSL_read (ssl, tls, sizeof(struct tls_header)); CHK_SSL(err);
	data_length = tls->tlsh_len;
	length = ntohs(data_length);
	total = length;
	do {
		len = SSL_read (ssl, ptr, length);
		ptr = ptr + len;
		length = length - len;
	} while (length > 0);
	write(tunfd, buff, total);
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	char  buf[300];

	X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
	printf("subject= %s\n", buf);

	if (preverify_ok == 1) {
		printf("Verification passed.\n");
	} else {
		int err = X509_STORE_CTX_get_error(x509_ctx);
		printf("Verification failed: %s.\n",
			X509_verify_cert_error_string(err));
	}
	return preverify_ok;
}

SSL* setupTLSClient(const char* hostname)
{
   // Step 0: OpenSSL library initialization 
   // This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	SSL_METHOD *meth;
	SSL_CTX* ctx;
	SSL* ssl;

	meth = (SSL_METHOD *)TLSv1_2_method();
	ctx = SSL_CTX_new(meth);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
	if(SSL_CTX_load_verify_locations(ctx, NULL, CA_DIR) < 1){
		printf("Error setting the verify locations. \n");
		exit(0);
	}
	ssl = SSL_new (ctx);

	X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
	X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

	return ssl;
}


int setupTCPClient(const char* hostname, int port)
{
	struct sockaddr_in server_addr;

   // Get the IP address from hostname
	struct hostent* hp = gethostbyname(hostname);

   // Create a TCP socket
	int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

   // Fill in the destination information (IP, port #, and family)
	memset (&server_addr, '\0', sizeof(server_addr));
	memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
   // server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14"); 
	server_addr.sin_port   = htons (port);
	server_addr.sin_family = AF_INET;

   // Connect to the destination
	connect(sockfd, (struct sockaddr*) &server_addr,
		sizeof(server_addr));

	return sockfd;
}

void send_credentials(SSL *ssl, char *user, char *passwd) {
	int err;
	char buff[4];
	memset(buff, 0, 4);
	struct tls_header *tls = (struct tls_header *) buff;
	char buffer[1500];
	memset(buffer, 0, 1500);
	struct cred_header *cred = (struct cred_header *) buffer; 
	cred->user_len = htons(strlen(user));
	cred->pwd_len = htons(strlen(passwd));
	char *data = buffer + sizeof(struct cred_header);
	strncpy(data, user, strlen(user));
	data = data + strlen(user);
	strncpy(data, passwd, strlen(passwd));
	cred->pckt_len = htons(strlen(user)+strlen(passwd)+sizeof(struct cred_header));
    // Sending the Length of the packet and then the packet itself.
	tls->tlsh_len = htons(cred->pckt_len);
	err = SSL_write(ssl, tls, sizeof(struct tls_header)); CHK_SSL(err);
	err = SSL_write(ssl, cred, cred->pckt_len); CHK_SSL(err); 
}

int reading_result(SSL *ssl) {
	int len, data_length, length, err;
	char buff[10];
	bzero(buff, 10);
	char *ptr = (char *)buff;
	int result;

	char buffer[4];
	memset(buffer, 0, 4);
	struct tls_header *tls = (struct tls_header *) buffer;

    // Reading the Packet length and then the packet
	err = SSL_read (ssl, tls, sizeof(struct tls_header)); CHK_SSL(err);
	data_length = tls->tlsh_len;
	length = ntohs(data_length);

	do {
		len = SSL_read (ssl, ptr, length);
		ptr = ptr + len;
		length = length - len;
	} while (length > 0);

	result = buff[0];
	return result;
}

void setup_login(int sockfd, SSL *ssl, char* user, char* password)
{
	int res;
	send_credentials(ssl, user, password);

	while (1) {
		fd_set readFDSet;
		FD_ZERO(&readFDSet);
		FD_SET(sockfd, &readFDSet);
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
		if (FD_ISSET(sockfd, &readFDSet)){
			res = reading_result(ssl);
			break;
		} 
	}
	
	if (res == 1) {
		printf("Awesome. You are now logged in!\n");
	}
	else {
		printf ("Uh-oh! Invalid Credentials. Please try again.");
		exit(1);
	}
}


int main (int argc, char * argv[]) {
	int tunfd, ch, i, res;
	char *hostname = "yahoo.com";
	int port = 443;
	char user[32];
	char *p;

	if (argc > 1) hostname = argv[1];
	if (argc > 2) port = atoi(argv[2]);
	tunfd  = createTunDevice();

   /*----------------TLS initialization ----------------*/
	SSL *ssl   = setupTLSClient(hostname);

   /*----------------Create a TCP connection ---------------*/
	int sockfd = setupTCPClient(hostname, port);

   /*----------------TLS handshake ---------------------*/
	SSL_set_fd(ssl, sockfd);

	int err = SSL_connect(ssl); CHK_SSL(err);
	printf("SSL connection is successful\n");
	printf ("SSL connection using %s\n", SSL_get_cipher(ssl));

	printf("Provide the username:");
	scanf("%s", user);

	p = getpass("Enter password: ");

	// printf("Sending login details \n");
	setup_login(sockfd, ssl, user, p);

	while(1) {
		fd_set readFDSet;
		FD_ZERO(&readFDSet);
		FD_SET(sockfd, &readFDSet);
		FD_SET(tunfd, &readFDSet);
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
		if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, ssl);
		if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, ssl);
	}
}

