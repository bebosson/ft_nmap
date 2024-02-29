#include "set_header.h"

#include <netinet/udp.h> // inet_addr
#include <arpa/inet.h> 
#include <netinet/tcp.h>


void		set_tcp_syn_header(void **tcp, int src_port, int dst_port)
{

	struct tcphdr **tcp_cpy; 

	tcp_cpy = (struct tcphdr **)tcp;
	(*tcp_cpy)->dest = htons(dst_port);
	(*tcp_cpy)->source = htons(src_port);
	(*tcp_cpy)->seq = htonl(50);
	(*tcp_cpy)->ack_seq = htonl(50);
	(*tcp_cpy)->doff = 5;
	(*tcp_cpy)->fin=0;
	(*tcp_cpy)->syn=1;
	(*tcp_cpy)->rst=0;
	(*tcp_cpy)->psh=0;
	(*tcp_cpy)->ack=0;
	(*tcp_cpy)->urg=0;
	(*tcp_cpy)->window = htons (5840);	/* maximum allowed window size */
	(*tcp_cpy)->check = 0;	//leave checksum 0 now, filled later by pseudo header
	(*tcp_cpy)->urg_ptr = 0;
}



void		set_tcp_ack_header(void **tcp, int src_port, int dst_port)
{
	struct tcphdr **tcp_cpy; 

	tcp_cpy = (struct tcphdr **)tcp;
	(*tcp_cpy)->dest = htons(dst_port);
	(*tcp_cpy)->source = htons(src_port);
	(*tcp_cpy)->seq = 50;
	(*tcp_cpy)->ack_seq = 50;
	(*tcp_cpy)->doff = 5;
	(*tcp_cpy)->fin=0;
	(*tcp_cpy)->syn=0;
	(*tcp_cpy)->rst=0;
	(*tcp_cpy)->psh=0;
	(*tcp_cpy)->ack=1;
	(*tcp_cpy)->urg=0;
	(*tcp_cpy)->window = htons (5840);	/* maximum allowed window size */
	(*tcp_cpy)->check = 0;	//leave checksum 0 now, filled later by pseudo header
	(*tcp_cpy)->urg_ptr = 0;
}

void		set_tcp_null_header(void **tcp, int src_port, int dst_port)
{
	struct tcphdr **tcp_cpy; 



	tcp_cpy = (struct tcphdr **)tcp;
	(*tcp_cpy)->dest = htons(dst_port);
	(*tcp_cpy)->source = htons(src_port);
	(*tcp_cpy)->seq = 50;
	(*tcp_cpy)->ack_seq = 50;
	(*tcp_cpy)->doff = 5;
	(*tcp_cpy)->fin=0;
	(*tcp_cpy)->syn=0;
	(*tcp_cpy)->rst=0;
	(*tcp_cpy)->psh=0;
	(*tcp_cpy)->ack=0;
	(*tcp_cpy)->urg=0;
	(*tcp_cpy)->window = htons (5840);	/* maximum allowed window size */
	(*tcp_cpy)->check = 0;	//leave checksum 0 now, filled later by pseudo header
	(*tcp_cpy)->urg_ptr = 0;
}

void		set_tcp_fin_header(void **tcp, int src_port, int dst_port)
{
	struct tcphdr **tcp_cpy; 

	tcp_cpy = (struct tcphdr **)tcp;
	(*tcp_cpy)->dest = htons(dst_port);
	(*tcp_cpy)->source = htons(src_port);
	(*tcp_cpy)->seq =  htonl(50);
	(*tcp_cpy)->ack_seq =  htonl(50);
	(*tcp_cpy)->doff = 5;
	(*tcp_cpy)->fin=1;
	(*tcp_cpy)->syn=0;
	(*tcp_cpy)->rst=0;
	(*tcp_cpy)->psh=0;
	(*tcp_cpy)->ack=0;
	(*tcp_cpy)->urg=0;
	(*tcp_cpy)->window = htons (5840);	/* maximum allowed window size */
	(*tcp_cpy)->check = 0;	//leave checksum 0 now, filled later by pseudo header
	(*tcp_cpy)->urg_ptr = 0;
}

void		set_tcp_xmas_header(void **tcp, int src_port, int dst_port)
{
	struct tcphdr **tcp_cpy; 


	tcp_cpy = (struct tcphdr **)tcp;
	(*tcp_cpy)->dest = htons(dst_port);
	(*tcp_cpy)->source = htons(src_port);
	(*tcp_cpy)->seq = 50;
	(*tcp_cpy)->ack_seq = 50;
	(*tcp_cpy)->doff = 5;
	(*tcp_cpy)->fin=1;
	(*tcp_cpy)->syn=0;
	(*tcp_cpy)->rst=0;
	(*tcp_cpy)->psh=1;
	(*tcp_cpy)->ack=0;
	(*tcp_cpy)->urg=1;
	(*tcp_cpy)->window = htons (5840);	/* maximum allowed window size */
	(*tcp_cpy)->check = 0;	//leave checksum 0 now, filled later by pseudo header
	(*tcp_cpy)->urg_ptr = 0;
}

void set_udp_header(void **header, int src_port, int dst_port)
{
	struct udphdr **udp_cpy; 

		udp_cpy = (struct udphdr **)header;

	(*udp_cpy)->source = htons(src_port);
	(*udp_cpy)->dest = htons(dst_port);
}
