#include "pack_reader.h"

#include "thread.h"
# include "ptr_scan.h"
#include "display_result.h"
#include <netinet/ip_icmp.h>


static t_port *tabprob_recv_scan(uint16_t scan_int, uint16_t port, t_env *env)
{
	int i;
	uint16_t bit_scan;
	uint16_t min;

	i = -1;
	min = env->scantab[0].min;
	while (++i < env->nb_scan)
	{
		bit_scan = *(uint16_t *)&env->scantab[i].scan_type;
		if (scan_int == bit_scan)
			return ((t_port *)&env->scantab[i].tabport[port - min]);
	}
	if (env->debug){printf("->%d<-\n", scan_int == bit_scan);}
	if (env->debug){printf("IMPOSSIBLE ! port = %d\n", port);}
	return (0);
}

int port_to_typescan(int port, t_env *env)
{
	int i;
	uint16_t scan;
	i = -1;
	while (++i < env->nb_scan)
	{
		if (port == env->portscan[i])
		{
			scan = *(uint16_t *)&env->scantab[i].scan_type;
			if (env->debug){print_scan(scan);}
			return (scan);
		}
	}
	return (-1);
}

static int get_src_and_dst(char *user, uint16_t *src, uint16_t *dst, bool inside, bool debug)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct udphdr *udp;
	char *ptr;
	int ret;

	if (inside == false)
		ip = (struct iphdr *)(user + sizeof(struct ether_header) + 2);
	else
		ip = (struct iphdr *)(user);
	if (ip->protocol == IPPROTO_UDP)
	{
		udp = (struct udphdr *)((char *)user + sizeof(struct iphdr));
		*src = ntohs(udp->uh_sport);
		*dst = ntohs(udp->uh_dport);
		return (1);
	}
	else if (ip->protocol == IPPROTO_TCP)
	{
		tcp = (struct tcphdr *)((char *)ip + sizeof(struct iphdr));
		*src = ntohs(tcp->source);
		*dst = ntohs(tcp->dest);
		return (1);
	}
	else if (ip->protocol == IPPROTO_ICMP)
	{
		ptr = (char *)((char *)ip + sizeof(struct iphdr) + sizeof(struct icmphdr));
		ret = get_src_and_dst(ptr, dst, src, true, debug);
		return (ret);
	}
	return (0);
}

int8_t	process_pkt(t_env *env)
{
	t_usercv *packet;
	uint16_t scanned_src;
	uint16_t scanned_dst;
	int 	scan;
	t_port *tabport_to_fill;

	packet = NULL;
	pthread_mutex_lock(&env->mtx_toprocess);
	if (env->toprocess)
	{
		packet = env->toprocess;
		if ( !(env->toprocess = env->toprocess->next))
			env->toprocess_head = NULL;
	}
	pthread_mutex_unlock(&env->mtx_toprocess);
	if (packet)
	{
		scanned_src = 0;
		scanned_dst = 0;
		get_src_and_dst(packet->user, &scanned_src, &scanned_dst, false, env->debug);
//		printf("AVANT source: %d | dest: %d | env->port_max = %d\n", scanned_src, scanned_dst, env->port_max);
		if (*(uint8_t *)&env->scanfield & SCAN_UDP && scanned_dst > env->port_max)
			scanned_dst = env->port_max;
//		printf("APRESsource: %d | dest: %d\n", scanned_src, scanned_dst);
		scan = port_to_typescan(scanned_dst, env);
		tabport_to_fill = tabprob_recv_scan(scan, scanned_src, env);
		if (!tabport_to_fill)
		{
//			if (env->debug){dprintf(2, "tabport_to_fill n'existe pas\n");}
			free(packet->user);
			free(packet);
			return (STOP);
		}
		if (tabport_to_fill->port_state == PORT_TO_SCAN)
		{
			if (!do_the_scan(scan, tabport_to_fill, packet, env->debug, &env->mtx_debug))
			{
				free(packet->user);
				free(packet);
				return (ERROR);
			}
		}
	pthread_mutex_lock(&env->mtx_recv_cnt); // cnt + reach_cnt
	env->recv_reachcnt++;
//	printf("--- env->recv_reachcnt = %d\n", env->recv_reachcnt);
	pthread_mutex_unlock(&env->mtx_recv_cnt);
		free(packet->user);
		free(packet);
		return (CARRY_ON);
	}
	else
	{

		if (env->retry_flag == 1)
		{
			struct timeval tv_cmp;

			gettimeofday(&tv_cmp, NULL);
			tvsub(&tv_cmp, &env->tv_retry);
			if (env->prep_done == true
					&& tv_cmp.tv_sec * 1000 + tv_cmp.tv_usec / 1000
					> env->limit + env->timeout / 1000
					&& env->recv_reachcnt == env->recv_cnt)
			{
				pthread_mutex_lock(&env->mtx_retry);
				if (env->retry_flag == 1)
				{
//		printf("RETRY_FLAG 1 -> 2\n");
					env->retry_flag = 2;
				}
				pthread_mutex_unlock(&env->mtx_retry);
			}
		}
		return (STOP);
	}
}

void	process_and_timeout(t_env *env)
{
	while (1)
	{
		struct timeval timeout;

		gettimeofday(&timeout, NULL);
		tvsub(&timeout, &env->tv_timeout);
		if (timeout.tv_sec * 1000000 + timeout.tv_usec > env->timeout_usec)
		{
			send_pkt_timeout(env);
			return ;
		}
		process_pkt(env);
	}
}

void	*process_th(void *arg)
{
	t_env *env;

	env = (t_env *)arg;

	while (1)
	{
		if (env->g_end == 1)
			return (NULL);
		process_pkt(env);
	}
}
