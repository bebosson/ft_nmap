#include "thread.h"

#include "send.h"
#include "pack_reader.h"
#include "set_pcap.h"


int    send_thread(t_env *env)
{
	if (pthread_create(&env->send_thread, NULL, send_th, env))
		return (0);
	return (1);
}

int		process_thread(t_env *env, int index)
{
	
	if (pthread_create(&env->process_thread[index], NULL, process_th, env))
		return (0);
	return (1);
}

int   pcap_thread(t_env *env)
{
	if (pthread_create(&env->pcap_thread, NULL, pcap_th, env))
		return (0);
	return (1);
}

void	send_pkt_timeout(t_env *env)
{
	t_probe probe = {.port_src = env->randport_timeout, .port_dst = env->randport_timeout, .typescan = SCAN_SYN};
	ft_send(env->send_sockfd, env->lo_addr, &probe, env->dev_addr, false, NULL);
}
