#ifndef THREAD_H
# define THREAD_H

#include "ft_nmap.h"


int     pcap_thread(t_env *env);
int     send_thread(t_env *env);
int		process_thread(t_env *env, int nb);
void	send_pkt_timeout(t_env *env);


void init_env(t_env *env);

#endif
