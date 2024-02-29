#include "set_pcap.h"

#include <netinet/ip_icmp.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <signal.h>

#define BUF_SIZE 1024
#define DATALEN 56

uint16_t in_cksum(uint16_t *addr, int len)
{
	int nleft = len;
	uint32_t sum = 0;
	uint16_t *w = addr;
	uint16_t answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1)
	{
		*(unsigned char *)(&answer) = *(unsigned char *)w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

struct timeval *recv_ping(t_env *env, int sockfd, struct icmp *src_pkt, struct sockaddr_in src_addr)
{
	int num_probes_received = 0;
	char buf[BUF_SIZE];
	socklen_t addrlen = sizeof(src_addr);
	struct pollfd fds[1];
	int timeout = 500;
	struct ip *ip;
	struct icmp *icmp;
	int hlen;
	int icmplen;
	struct timeval *tv_recv;

	ft_memset(buf, 0, BUF_SIZE);
	while (num_probes_received < 1)
	{
		fds[0].fd = sockfd;
		fds[0].events = POLLIN;
		fds[0].revents = 0;

		int ret = poll(fds, 1, timeout);
		if (ret > 0)
		{
			int recv_len = recvfrom(sockfd, buf, BUF_SIZE, 0, (struct sockaddr *)&src_addr, &addrlen);
			if (recv_len > 0)
			{
				// Extraction de l'adresse IP source
				char src_ip[INET_ADDRSTRLEN];
				char dst_ip[INET_ADDRSTRLEN];
				if (inet_ntop(AF_INET, &(src_addr.sin_addr), src_ip, INET_ADDRSTRLEN) == NULL)
				{
					perror("Erreur lors de l'extraction de l'adresse IP source");
					return (NULL);
				}
				ip = (struct ip *)buf;  /* start of IP header */

				if (inet_ntop(AF_INET, &(env->dev_addr.s_addr), dst_ip, INET_ADDRSTRLEN) == NULL)
				{
					perror("Erreur lors de l'extraction de l'adresse IP source");
					return (NULL);
				}
				if(ft_memcmp(dst_ip, inet_ntoa(ip->ip_dst), sizeof(INET_ADDRSTRLEN)))
				{
					if (env->debug){printf("error addr \n");}
					return (NULL);
				}
				hlen = ip->ip_hl << 2; /* length of IP header */
				if (ip->ip_p != IPPROTO_ICMP)
					return (NULL);                          /* not ICMP */
				icmp = (struct icmp *)(buf + hlen); /* start of ICMP header */
				if ((icmplen = recv_len - hlen) < 8)
					return (NULL); /* malformed packet */
				if (icmp->icmp_type == ICMP_ECHOREPLY)
				{
					if (icmp->icmp_id != src_pkt->icmp_id)
						return (NULL); /* not a response to our ECHO_REQUEST */
					if (icmplen < 16)
						return (NULL);
					num_probes_received++;
				}
			}
		}
		else if (ret == 0)
		{
			printf("Timeout elapsed\n");
			return (NULL);
		}
		else
		{
			perror("poll");
			exit(EXIT_FAILURE);
		}
	}

	if ( !(tv_recv = ft_memalloc(sizeof(struct timeval))))
		return (NULL);
	gettimeofday(tv_recv, NULL);
	return (tv_recv);
}

int send_ping(t_env *env)
{
	int len;
	struct icmp *icmp;
	int datalen;
	char sendbuf[64];
	int data_send = 0;
	int id = 1;
	int sockfd;
	struct timeval tv_send;
	struct timeval *tv_recv;

	// Create a raw socket for ICMP
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	icmp = (struct icmp *)sendbuf;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_id = id;
	icmp->icmp_seq = 0;
	datalen = DATALEN; // header_len
	ft_memset(icmp->icmp_data, 0, datalen);
	gettimeofday((struct timeval *)icmp->icmp_data, NULL);
	len = 8 + datalen; /* checksum ICMP header and data */
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((u_short *)icmp, len);
	gettimeofday(&tv_send, NULL);
	for (int i = 0; i < 1; i++)
	{
		if((data_send = sendto(sockfd, sendbuf, len, 0,
						(struct sockaddr *)&env->pars->dest_saddr, env->pars->salen)) < 0)
		{
			printf("sendto: le reseau n'est pas accessible\n");
			exit(EXIT_SUCCESS);
		}
	}
	if ( !(tv_recv = recv_ping(env, sockfd, icmp, env->pars->dest_saddr)))
		return (-1);
	tvsub(tv_recv, &tv_send);
	env->timeout = ((tv_recv->tv_sec * 1000000 + tv_recv->tv_usec) * 125) / 100;
	if (env->debug) {printf("timeout = %.2f ms\n", (float)env->timeout / 1000);}
	free(tv_recv);
	return (0);
}

static int save_device(t_env *env)
{
	pcap_if_t *alldevs;
	pcap_if_t *dev_head;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp = 0;
	bpf_u_int32 maskp = 0;
	struct in_addr net_addr, net_mask;


	ft_memset(errbuf, 0, sizeof(errbuf));
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		printf("error findalldevs\n");
		exit_free(env);
	}
	dev_head = alldevs;
	while (dev_head->next != NULL)
	{
		if ((dev_head->flags & (PCAP_IF_UP | PCAP_IF_RUNNING))
				&& pcap_lookupnet(dev_head->name, &netp, &maskp, errbuf) == 0)
		{
			net_mask.s_addr = maskp;
			net_addr.s_addr = netp;
			struct pcap_addr *addresses = dev_head->addresses;
			while (addresses)
			{
				struct in_addr *dev_addr;
				dev_addr = &((struct sockaddr_in *)addresses->addr)->sin_addr;
				unsigned long sadr = dev_addr->s_addr & net_mask.s_addr;
				ft_memcpy(&env->dev_addr, dev_addr, sizeof(struct in_addr));
				if (((struct in_addr *)(&sadr))->s_addr == net_addr.s_addr)
				{
					if (send_ping(env) == 0)
					{
						pcap_freealldevs(alldevs);
						return (1);
					}
				}
				addresses = addresses->next;
			}
		}
		dev_head = dev_head->next;
	}
	pcap_freealldevs(alldevs);
	return (-1);

}

static void save_recv(t_sending_pair *sending_pair, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	t_usercv *node;

	node = ft_memalloc(sizeof(t_usercv));
	node->user = ft_memalloc(pkthdr->len);
	ft_memcpy(node->user, packet, pkthdr->len);
	if (sending_pair->listrcv_head)
	{
		sending_pair->listrcv_head->next = node;
		sending_pair->listrcv_head = sending_pair->listrcv_head->next;
	}
	else
	{
		sending_pair->listrcv = node;
		sending_pair->listrcv_head = sending_pair->listrcv;
	}
}

void	pre_send_handle(t_env *env, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	if (env->first_pkt_arrived == false)
	{
		gettimeofday(&env->timecapture, NULL);
		env->first_pkt_arrived = true;
	}
	struct timeval tv_cmp;

	save_recv(env->testing_pair, pkthdr, packet);
	gettimeofday(&tv_cmp, NULL);
	tvsub(&tv_cmp, &env->timecapture);
	if (!tv_cmp.tv_sec && tv_cmp.tv_usec <= 10000)
	{
		env->prerecv_packet++;
		if (env->prerecv_packet == env->process_capacity)
		{
			if (env->flag_prercv == GOING_UP)
			{
				env->process_capacity *= 2;
				env->prerecv_packet = 0;
				env->first_pkt_arrived = false;
			}
			else
				env->flag_prercv = GOOD_VALUE;
		}
	}
	else
	{
		env->surplus++;
		if (env->prerecv_packet + env->surplus == env->process_capacity)
		{
			env->process_capacity = env->prerecv_packet;
			env->prerecv_packet = 0;
			env->flag_prercv = GOING_DOWN;
			env->first_pkt_arrived = false;
		}

	}
}

static void handle_IP(u_char *user_buffer, const struct pcap_pkthdr* pkthdr,const u_char* packet)
{

	const struct ip* ip;
	uint16_t length = pkthdr->len;
	uint16_t hlen;
	struct tcphdr *tcph;
	t_env *env;

	env = (t_env *)user_buffer;
	uint16_t len;
	/* jump pass the linux cooked header */
	ip = (struct ip *)(packet + 16);
	len     = ntohs(ip->ip_len);
	// hlen    = IP_HL(ip); /* header length */
	hlen = ((ip)->ip_hl & 0x0f);
	//  version = IP_V(ip);/* ip version */ // IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
	/* check header length */
	if(hlen < 5)
		fprintf(stdout,"bad-hlen %d \n",hlen);
	/* see if we have as much packet as we should */
	if(length < len)
	{
		printf("\ntruncated IP - %d bytes missing\n",len - length);
		return ;
	}
	tcph = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + 2);
	
	if (ft_strequ(inet_ntoa(ip->ip_src), inet_ntoa(env->dev_addr))
			&& ntohs(tcph->dest) == env->randport_timeout)
	{
		if (env->flag_prercv != GOOD_VALUE && ntohs(tcph->source) == 1312)
			pre_send_handle(env, pkthdr, packet);
//		else
//		{
//			printf("timeout: ip.src = %s", inet_ntoa(ip->ip_src));
//			printf("  .dst = %s | tcp.src = %d  .dst = %d\n", inet_ntoa(ip->ip_dst), ntohs(tcph->source), ntohs(tcph->dest));
//		}
		return;
	}

//	printf("un tour: ip.src = %s", inet_ntoa(ip->ip_src));
//	printf("  .dst = %s | tcp.src = %d  .dst = %d\n", inet_ntoa(ip->ip_dst), ntohs(tcph->source), ntohs(tcph->dest));
	pthread_mutex_lock(&env->mtx_recv);
	save_recv(env->sending_pair, pkthdr, packet);
	pthread_mutex_unlock(&env->mtx_recv);
	env->recv_cnt++;
//	printf("+++ env->recv_cnt = %d\n", env->recv_cnt);
}

	static void
ft_pcap_freecode(struct bpf_program *program)
{
	program->bf_len = 0;
	if (program->bf_insns) {
		free((void *)program->bf_insns);
		program->bf_insns = NULL;
	}
}

char *get_port_filter(t_env *env)
{
	char *ret_tmp1;
	char *port_max;
	int ext;
	char *port_min = ft_itoa(env->portscan[0]);
	if (env->nb_scan > 1)
	{
		char *dst_portrange = " and dst portrange ";
		char *underscore = ft_strjoin(port_min, "-");
		if ( (ext = env->size_listsend / env->nb_scan) >= 100)
			ext = 99;
		if (*(uint8_t *)&env->scanfield & SCAN_UDP && ext)
			port_max = ft_itoa(env->portscan[env->nb_scan - 1] + ext);
		else
			port_max = ft_itoa(env->portscan[env->nb_scan - 1]);
		char *port_range = ft_strjoin(underscore, port_max);
		ret_tmp1 = ft_strjoin(dst_portrange, port_range);
		free(underscore);
		free(port_max);
		free(port_range);
	}
	else
		ret_tmp1 = ft_strjoin(" and dst port ", port_min);
	free(port_min);
	return (ret_tmp1);

}

static int ft_pcap_open_live(t_env *env)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program bpf;
	int ret_pcap_compile;
	int ret_pcap_setfilter;

	const char s[] = "(src host ";
	char *pkt_tmp1 = ft_strjoin(s, env->pars->buf_addr);
	char *tmp_get_port_filter = get_port_filter(env);
	char *pkt_tmp2 = ft_strjoin(pkt_tmp1, tmp_get_port_filter);
	free(pkt_tmp1);
	free(tmp_get_port_filter);
	char *srcport_t_o = ft_itoa(env->randport_timeout);
	char *t_o_dst = ft_strjoin(srcport_t_o, ")");
	free(srcport_t_o);
	char *t_o_filter = ft_strjoin(" or (src host 127.0.0.1 and dst port ", t_o_dst);
	free(t_o_dst);

	if(!(env->handle = pcap_open_live("any", 150, 0, 100, errbuf)))
		return (0);

	char *pkt_filter = ft_strjoin(pkt_tmp2, ")");
	free(pkt_tmp2);
	char *tcp_udp_filter = ft_strjoin(pkt_filter, t_o_filter);
	free(pkt_filter);
	free(t_o_filter);
	char *tmp_icmp_filter = ft_strjoin(" or (icmp and src host ", env->pars->buf_addr);
	char *icmp_filter = ft_strjoin(tmp_icmp_filter, ")");
	char *filter = ft_strjoin(tcp_udp_filter, icmp_filter);
	if (env->debug)
		printf("filter: %s\n", filter);
	free(tmp_icmp_filter);
	free(icmp_filter);
	free(tcp_udp_filter);

	if ( (ret_pcap_compile = pcap_compile(env->handle, &bpf ,filter, 0, PCAP_NETMASK_UNKNOWN)))
		return (0);

	free(filter);
	if ( (ret_pcap_setfilter = pcap_setfilter(env->handle, &bpf)))
		return (0);
	ft_pcap_freecode(&bpf);
	return (1);
}

void	sendback(t_env *env)
{
	env->listsend = env->sendback;
	env->sendback = NULL;
	env->retry_flag = 0;
	env->tries++;
	env->recv_cnt = 0;
	env->recv_reachcnt = 0;
	if (env->tick_count == env->size_listsend)
		env->g_end = 1;
	ft_memset(&env->tv_retry, 0, sizeof(struct timeval));
//	printf("on renvoie tout\n");
}


t_sending_pair	*init_sending_pair(void)
{
	t_sending_pair *node;

	if ( !(node = ft_memalloc(sizeof(t_sending_pair))))
		return (NULL);
	node->listsending = NULL;
	node->listsending_head = NULL;
	node->listrcv = NULL;
	return (node);
}

void	filter_empty(t_env *env, t_sending_pair *pair)
{
	if (pair)
	{
		if (pair->listsending)
		{
			if (!env->sendback)
			{
				env->sendback = pair->listsending;
				env->sendback_head = pair->listsending_head;
			}
			else
			{
				(env->sendback_head)->next = pair->listsending;
				env->sendback_head = pair->listsending_head;
			}
		}
		if (pair->listrcv)
		{
			pthread_mutex_lock(&env->mtx_toprocess);
			if (!env->toprocess)
			{
				env->toprocess = pair->listrcv;
				env->toprocess_head = pair->listrcv_head;
			}
			else
			{
				env->toprocess_head->next = pair->listrcv;
				env->toprocess_head = pair->listrcv_head;
			}
			pthread_mutex_unlock(&env->mtx_toprocess);
		}
		free(pair);
	}
}

void	set_env(t_env *env)
{
	filter_empty(env, env->sending_pair);
	env->sending_pair = init_sending_pair();
	env->send_packet = 0;
	pthread_mutex_unlock(&env->mtx_wait);
}

void ft_pcap_dispatch(t_env *env)
{
	pcap_dispatch(env->handle, -1, handle_IP , (u_char *)env);
}

void	*pcap_th(void *arg)
{
	t_env *env;

	env = (t_env *)arg;
	while (1)
	{
		if (env->tick_count == env->size_listsend)
		{
			env->g_end = 1;
			filter_empty(env, env->sending_pair);
			return (NULL);
		}
		pthread_mutex_lock(&env->mtx_recv);
		set_env(env);
		pthread_mutex_unlock(&env->mtx_recv);
		if (env->retry_flag == 2)
			sendback(env);
		ft_pcap_dispatch(env);
	}

}

int 	ft_pcap_init(t_env *env)
{
	if(save_device(env) < 0)
	{
		printf("pcap_init_fail: no interface available found, are you sure this address exist?\n");
		exit_free(env);
	}
	if(!ft_pcap_open_live(env))
		return (0);
	return (1);
}
