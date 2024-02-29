#include "exec.h"

#include "libft.h"
#include "thread.h"
#include "send.h"
#include "pack_reader.h"
#include "set_pcap.h"

#include <signal.h>


t_timeout_env g_timeout_env = {0};

int		multi_th_exec(t_env *env)
{
	pthread_mutex_lock(&env->mtx_wait);
	if (!pcap_thread(env))
			return (0);
	for (int nb_thread_process = 0; nb_thread_process < env->nbprocess_th; nb_thread_process++)
	{
		if (!process_thread(env, nb_thread_process))
			return(0);
	}
	send_th((void*)env);
	for (int nb_thread_process = 0; nb_thread_process < env->nbprocess_th; nb_thread_process++)
		pthread_join(env->process_thread[nb_thread_process], NULL);
	return (1);
}

void	sigalarm_timeout()
{
	struct in_addr lo_addr;
	t_probe probe = {.port_src = g_timeout_env.port, .port_dst = g_timeout_env.port, .typescan = SCAN_SYN};
	inet_pton(AF_INET, "127.0.0.1", &lo_addr);
	ft_send(g_timeout_env.fd, lo_addr, &probe, g_timeout_env.dev_addr, false, NULL);
}

static int		single_th_exec(t_env *env)
{
	bool carry_on;
	struct sigaction action;
	struct timeval start;
	struct timeval frequency;
	int8_t ret;

	g_timeout_env.fd = env->send_sockfd;
	g_timeout_env.port = env->randport_timeout;
	ft_memcpy(&g_timeout_env.dev_addr, &env->dev_addr, sizeof(struct in_addr));

	action.sa_handler = sigalarm_timeout;
	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
	sigaction(SIGALRM, &action, NULL);
	env->recv_packet_max = 100;
	env->pck_max_ref = 100;
	while (1)
	{
		carry_on = true;
		if (env->tick_count == env->size_listsend)
		{
			alarm(0);
			free(env->sending_pair);
			free(env->testing_pair);
			return (1);
		}
		while (carry_on)
		{
			set_env(env);
			carry_on = send_batch(env);
			gettimeofday(&start, NULL);
			alarm(1);
			ft_pcap_dispatch(env);
			do {
				process_pkt(env);
				gettimeofday(&frequency, NULL);
				tvsub(&frequency, &start);
			} while (frequency.tv_sec * 1000 + frequency.tv_usec / 1000 < 1000);
		}
		do {
			ret = process_pkt(env);
			if (ret == ERROR)
				return (0);
		} while (ret == CARRY_ON);
		sendback(env);
	}
}

int		exec_nmap(t_env *env)
{
	if (env->total > 1)
	{
		if (!multi_th_exec(env))
			return (0);
	}
	else if (!single_th_exec(env))
		return (0);
	return (1);
}
