#ifndef SET_PCAP_H
#define SET_PCAP_H

#include "ft_nmap.h"


int     ft_pcap_init(t_env *env);
void    ft_pcap_dispatch(t_env *env);
void	*pcap_th(void *arg);
void	sendback(t_env *env);
void	set_env(t_env *env);
t_sending_pair	*init_sending_pair(void);

#endif
