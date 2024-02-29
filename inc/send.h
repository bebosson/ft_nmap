#ifndef SEND_H
#define SEND_H

#include "ft_nmap.h"


// 96 bit (12 bytes) pseudo header needed for tcp and udp header checksum calculation
struct pseudo_header
{
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t placeholder;
	uint8_t protocol;
	uint16_t tcp_length;
};


int		check_retry_tabscan(t_probe *probe , t_env *env);
bool	send_batch(t_env *env);
void	pre_send(t_env *env);
void	*send_th(void *arg);
int		ft_send(int sockfd, struct in_addr dest_addr, t_probe *probe, struct in_addr dev_addr, bool debug, pthread_mutex_t *mtx_debug);

#endif
