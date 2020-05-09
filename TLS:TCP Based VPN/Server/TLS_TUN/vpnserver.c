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

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

#define BUFF_SIZE 2000

struct tls_header {
   unsigned short int tlsh_len;
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
    int  length, err;
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
    err = SSL_read(ssl, tls, sizeof(struct tls_header)); CHK_SSL(err);
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

int setupTCPServer(int port)
{
    struct sockaddr_in sa_server;
    int listen_sock;
    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (port);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

int main (int argc, char * argv[]) {
   int tunfd, port = 4433;
   if (argc > 1) port = atoi(argv[1]);

   tunfd  = createTunDevice();

   SSL_METHOD *meth;
   SSL_CTX* ctx;
   SSL *ssl;
   int err;

  // Step 0: OpenSSL library initialization 
  // This step is no longer needed as of version 1.1.0.
  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  // Step 1: SSL context initialization
  meth = (SSL_METHOD *)TLSv1_2_method();
  ctx = SSL_CTX_new(meth);

  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  // Step 2: Set up the server certificate and private key
  SSL_CTX_use_certificate_file(ctx, "../server_cert/server-cert.pem", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, "../server_cert/server-key.pem", SSL_FILETYPE_PEM);
  // Step 3: Create a new SSL structure for a connection
  ssl = SSL_new (ctx);

  struct sockaddr_in sa_client;
  size_t client_len;
  int listen_sock = setupTCPServer(port);

  while(1){
    int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
    printf ("TCP connection established!\n");
    if (fork() == 0) { // The child process
      close (listen_sock);
      SSL_set_fd (ssl, sock);
      int err = SSL_accept (ssl);
      CHK_SSL(err);
      printf ("SSL connection established!\n");

      while (1) {
          fd_set readFDSet;
      	  FD_ZERO(&readFDSet);
      	  FD_SET(tunfd, &readFDSet);
      	  FD_SET(sock, &readFDSet);
          select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

          if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, ssl);
          if (FD_ISSET(sock, &readFDSet)) socketSelected(tunfd, ssl);
	}
      close(sock);
      return 0;
      } 
      else { // The parent process
              close(sock);
          }
    }
}
