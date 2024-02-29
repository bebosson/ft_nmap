#ifndef FT_NMAP_H
# define FT_NMAP_H

#include "libft.h"

#include <pcap/pcap.h>
#include <stdbool.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>	//Provides declarations for ip header
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/udp.h>	//Provides declarations for tcp header
#include <netinet/if_ether.h>	//Provides declarations for tcp header
#include <arpa/inet.h>	//Provides declarations for tcp header
#include <pthread.h>


#define ID_PACKET 15019
#define GOING_UP 1
#define GOING_DOWN 0
#define GOOD_VALUE 2
#define STOP 0
#define CARRY_ON 1
#define ERROR -1


enum stateport {
	PORT_TO_SCAN = 1,
	PORT_OPEN,
	PORT_CLOSE,
	PORT_FILTER,
	PORT_UNFILTER,
	PORT_OPEN_FILTER,
};

enum typescan {
	SCAN_SYN = 1,
	SCAN_ACK = 2,
	SCAN_NULL = 4,
	SCAN_FIN = 8,
	SCAN_XMAS = 16,
	SCAN_UDP = 32
};

typedef struct	s_pars
{
	char *str_port_range;
	int *pars_port; // [10..20]
	int range_port; // 10
	char *buf_addr; //8.8.8.8
	struct sockaddr_in dest_saddr;
	socklen_t salen;
} t_pars;

typedef struct	s_parsline
{
	char **av;
	int ac;
	int addr;
	int port_index;
	bool file;
	bool debug;
	int thread;
	struct s_parsline *next;
} t_parsline;

typedef struct s_port // s_type_sin, s_type_ack...
{
	uint8_t port_state; //OPEN, CLOSE...
	uint8_t tries; //nbre de tries 
} t_port;

typedef struct	s_scanbits
{
	uint8_t SYN:1;
	uint8_t ACK:1;
	uint8_t NUL:1;
	uint8_t FIN:1;
	uint8_t XMAS:1;
	uint8_t UDP:1;
} t_scanbits;

typedef struct	s_probe{
	int8_t typescan;
	uint16_t port_src;
	uint16_t port_dst;
	struct timeval start;
	struct s_probe *prev;
	struct s_probe *next;
} t_probe;

typedef struct	s_scan
{
	//send
	t_probe *listprobe;
	//receive
	t_scanbits scan_type;
	uint16_t min;
	uint32_t range_port;
	uint32_t nb_port;
	t_port *tabport;
}				t_scan;

typedef struct	s_usercv
{
	char *user;
	struct s_usercv *next;
} t_usercv;

typedef struct s_sending_pair
{
	t_probe *listsending;
	t_probe *listsending_head;
	t_usercv *listrcv;
	t_usercv *listrcv_head;

} t_sending_pair;

typedef struct	s_env
{
/*---------PARSING---------*/
	t_pars *pars;
	struct in_addr dev_addr;
	struct in_addr dest_addr;
	struct in_addr lo_addr;
	uint8_t flag_troll;
	bool debug;
	int *scanned_ports;
	int scanned_ports_len;


/*---------PRE SCAN--------*/
	t_sending_pair *testing_pair;
	uint8_t flag_prercv;
	uint16_t prerecv_packet;
	struct timeval timecapture;
	int process_capacity;
	long limit;
	bool prep_done;
	int surplus;


/*-----------SCAN----------*/
	int send_sockfd;
	int fd_result;
	uint8_t nb_scan; //1-6
	t_scanbits scanfield;
	t_scan *scantab; // 1 par scan
	uint16_t *portscan; // tabrandom_port
	uint16_t port_max;
	bool first_loop;
	bool first_pkt_arrived;
	uint16_t randport_timeout;
	t_probe *listsend;
	t_probe *listsend_head;
	t_probe *sendback;
	t_probe *sendback_head;
	uint32_t size_listsend;
	pcap_t *handle;
	pthread_t send_thread;
	pthread_t pcap_thread;
	pthread_t verif_timeout;
	pthread_t process_thread[250];
	uint32_t total;
	int16_t nbprocess_th;
	struct timeval tv_retry;
	struct timeval tv_timeout;
	long timeout;
	uint32_t timeout_usec;
	int tries;
	int recv_cnt;
	uint16_t send_packet;
	uint16_t recv_packet_max;
	uint16_t pck_max_ref;
	int g_end;


/*----------SHARED---------*/
	pthread_mutex_t	mtx_toprocess;
	t_usercv *toprocess;
	t_usercv *toprocess_head;

	pthread_mutex_t	mtx_tick_count;
	uint32_t tick_count;

	pthread_mutex_t	mtx_retry;
	int retry_flag;

	pthread_mutex_t	mtx_recv;
	t_sending_pair *sending_pair;

	pthread_mutex_t mtx_recv_cnt;
	int recv_reachcnt;

	pthread_mutex_t	mtx_wait;
	pthread_mutex_t	mtx_debug;
} t_env;


void exit_free(t_env *env);

static inline void
tvsub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) {
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

#endif
