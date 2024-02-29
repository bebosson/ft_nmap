#include "send.h"

#include "set_env.h"
#include "ptr_scan.h"
#include "pack_reader.h"
#include "display_result.h"
#include "ft_nmap.h"

uint16_t checksum(uint16_t *buf, int nwords) {
	uint32_t sum = 0;
	while (nwords > 1) {
		sum += *buf++;
		nwords -= 2;
	}
	if (nwords > 0) {
		sum += *(uint8_t *)buf;
	}
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	return ~sum;
}

static void set_ip_header(char *datagram, struct iphdr **iph, struct in_addr dest_addr,
		struct in_addr dev_addr, int datalen, t_probe *probe)
{
	static int id_packet = ID_PACKET;

	(*iph)->ihl = 5;
	(*iph)->version = 4;
	(*iph)->tos = 0;
	if (probe->typescan == SCAN_UDP)
	{
		(*iph)->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + datalen;
		(*iph)->protocol = IPPROTO_UDP;
	}
	else
	{
		(*iph)->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + datalen;
		(*iph)->protocol = IPPROTO_TCP;
	}
	(*iph)->id = htons(id_packet++);	//Id of this packet
	(*iph)->frag_off = 0;
	(*iph)->ttl = 255;
	(*iph)->check = 0;		//Set to 0 before calculating checksum
	(*iph)->saddr = dev_addr.s_addr;
	(*iph)->daddr = dest_addr.s_addr;
	(*iph)->check = checksum ((unsigned short *) datagram, (*iph)->tot_len);
}

int ft_send(int sockfd, struct in_addr dest_addr, t_probe *probe, struct in_addr dev_addr, bool debug, pthread_mutex_t *mtx_debug)
{
	void *header;
	size_t header_struct;
	int		protocol;
	int ret;
	//Datagram to represent the packet
	char datagram[4096], *data, *pseudogram;
	ft_memset(datagram, 0, 4096);

	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;

	if (probe->typescan == SCAN_UDP)
	{
		header = (struct udphdr *)(datagram + sizeof(struct ip));
		header_struct = sizeof(struct udphdr);
		protocol = IPPROTO_UDP;
	}
	else
	{
		header = (struct tcphdr *)(datagram + sizeof(struct ip));
		header_struct = sizeof(struct tcphdr);
		protocol = IPPROTO_TCP;
	}

	struct sockaddr_in sin;
	struct pseudo_header psh;

	//Data part
	data = datagram + sizeof(struct iphdr) + header_struct;
	if (probe->typescan != SCAN_UDP)
		strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = dest_addr.s_addr;


	set_ip_header(datagram, &iph, dest_addr, dev_addr, ft_strlen(data), probe);//add protocol in the ip function
	setheader(probe, &header);


	//Now the TCP checksum
	psh.source_address = dev_addr.s_addr;
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = protocol; //sender->protocol
	psh.tcp_length = htons(header_struct + strlen(data));

	int psize = sizeof(struct pseudo_header) + header_struct + strlen(data);
	pseudogram = malloc(psize);

	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , header, header_struct + strlen(data));

	if (protocol == IPPROTO_TCP)
	{
		struct tcphdr *tcp = (struct tcphdr *)header;
		tcp->check = checksum( (unsigned short*) pseudogram , psize);
		if (debug)
		{
			pthread_mutex_lock(mtx_debug);
			ret = print_tcp_pkt(iph, tcp);
			pthread_mutex_unlock(mtx_debug);
			if (!ret)
				return (0);
		}
//	printf("send: ip.src = %s", inet_ntoa(*(struct in_addr*)&iph->saddr));
//	printf("  .dst = %s | tcp.src = %d  .dst = %d\n",
//			inet_ntoa(*(struct in_addr*)&iph->daddr), tcp->source, tcp->dest);

	}
	else if ((protocol == IPPROTO_UDP))
	{
		struct udphdr *udp = (struct udphdr*)header;
		udp->len = htons(header_struct + strlen(data));
		udp->check = 0;
		if (debug)
		{
			pthread_mutex_lock(mtx_debug);
			ret = print_udp_pkt(iph, udp);
			pthread_mutex_unlock(mtx_debug);
			if (!ret)
				return (0);
		}
	}

	int one = 1;
	const int *val = &one;

	//IP_HDRINCL to tell the kernel that headers are included in the packet
	if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		exit(0);
	}
	if (sendto (sockfd, datagram, iph->tot_len , 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
	{
		perror("sendto failed");
		exit(EXIT_SUCCESS);
	}
	if (gettimeofday(&probe->start, NULL) == -1)
		return (0);
	free(pseudogram);

	return (1);
}

int check_retry_tabscan(t_probe *probe , t_env *env)
{
	int i;
	uint16_t bit_scan;
	uint16_t min;
	t_port *tabport;
	i = -1;

	while (++i < env->nb_scan)
	{
		bit_scan = *(uint16_t *)&env->scantab[i].scan_type;
		if (probe->typescan == bit_scan)
		{
			min = env->scantab[i].min;
			tabport = &(env->scantab[i].tabport[probe->port_dst - min]);
			if (tabport->tries < 2 && tabport->port_state == PORT_TO_SCAN)
			{
				tabport->tries++;
				return (1);
			}
			else if (tabport->tries == 2 && tabport->port_state == PORT_TO_SCAN)
			{
				do_the_scan(probe->typescan, tabport, NULL, false, NULL);
				pthread_mutex_lock(&env->mtx_tick_count);
				env->tick_count += 1;
				pthread_mutex_unlock(&env->mtx_tick_count);
				return (0);
			}
			else if (tabport->port_state != PORT_TO_SCAN)
			{
				pthread_mutex_lock(&env->mtx_tick_count);
				env->tick_count += 1;
				pthread_mutex_unlock(&env->mtx_tick_count);
				return (0);
			}
		}
	}
	return (2);
}

int		pop_or_send(t_env *env, t_probe *extracted_probe)
{
	int ret;

	if (!check_retry_tabscan(extracted_probe, env))
	{
		free(extracted_probe);
	}
	else
	{
		pthread_mutex_lock(&env->mtx_recv);
		if ( (ret = ft_send(env->send_sockfd, env->dest_addr,
						extracted_probe, env->dev_addr, env->debug, &env->mtx_debug)))
		{
			if (env->sending_pair && env->sending_pair->listsending_head)
			{
				extracted_probe->next = NULL;
				env->sending_pair->listsending_head->next = extracted_probe;
				env->sending_pair->listsending_head = env->sending_pair->listsending_head->next;
			}
			else
			{
				env->sending_pair->listsending = extracted_probe;
				env->sending_pair->listsending->next = NULL;
				env->sending_pair->listsending_head = env->sending_pair->listsending;
			}
		}
		env->send_packet++;
		pthread_mutex_unlock(&env->mtx_recv);
		if (!ret)
			return (0);
	}
	return (1);
}

t_probe	*get_next_probe(t_env *env)
{
	t_probe *next_probe;

	next_probe = NULL;
	if (env->listsend)
	{
		next_probe = env->listsend;
		if (next_probe->typescan == SCAN_UDP)
		{
			env->recv_packet_max = 1;
			if (env->tries == 1)
				env->timeout_usec = 500000;
			else
				env->timeout_usec = 1000000;
		}
		else
		{
			env->recv_packet_max = env->pck_max_ref;
			env->timeout_usec = 100000;
		}
		if ( !(env->listsend = env->listsend->next))
			env->listsend_head = NULL;
	}
	return (next_probe);
}

bool	send_batch(t_env *env)
{
	t_probe *probe;
	int carry_on;

	carry_on = true;
	gettimeofday(&env->tv_timeout, NULL);
	while (env->send_packet < env->recv_packet_max)
	{
		if ( (probe = get_next_probe(env)))
			pop_or_send(env, probe);
		else
		{

			pthread_mutex_lock(&env->mtx_retry);
			if (env->retry_flag == 0)
			{
//		printf("RETRY_FLAG 0 -> 1\n");
				env->retry_flag = 1;
				gettimeofday(&env->tv_retry, NULL);
			}
			pthread_mutex_unlock(&env->mtx_retry);

			carry_on = false;
			break;
		}
	}
	return (carry_on);
}

t_probe    *add_probe(t_probe *probe)
{
	t_probe *new_probe;

	if (! (new_probe = ft_memalloc(sizeof(t_probe))))
		return (NULL);
	ft_memcpy(new_probe, probe, sizeof(t_probe));
	return (new_probe);
}

t_probe *create_timeoutlist(t_env *env)
{
	t_probe *listsend = NULL;
	t_probe *new_probe;
	int i = -1;
	t_probe probe = {.port_src = env->randport_timeout, .port_dst = 1312, .typescan = SCAN_SYN};

	while(++i < env->process_capacity)
	{
		new_probe = add_probe(&probe);
		new_probe->next = listsend;
		listsend = new_probe;
	}
	return (listsend);
}

void pre_send(t_env *env)
{
	t_probe *timeout_list;
	bool loop = true;
	t_probe *tmp = NULL;
	t_probe *next = NULL;
	int cmp = 0;
	env->flag_prercv = GOING_UP;
	while (loop)
	{
		if (cmp != env->process_capacity)
		{
			timeout_list = create_timeoutlist(env);
			tmp = timeout_list;
			cmp = env->process_capacity;
			env->surplus = 0;
		}
		int i = 0;
		while (tmp)
		{
			i++;
			ft_send(env->send_sockfd, env->lo_addr, tmp, env->dev_addr, false, NULL);
			next = tmp->next;
			free(tmp);
			tmp = next;
		}
		if (env->flag_prercv == GOOD_VALUE)
		{
			loop = false;
			t_usercv *tmp_free;
			t_usercv *next;
			tmp_free = env->testing_pair->listrcv;
			while (tmp_free)
			{
				next = tmp_free->next;
				free(tmp_free->user);
				free(tmp_free);
				tmp_free = next;
			}
			free(env->testing_pair);
		}
	}
	int frequency;
	if ( !(frequency = env->process_capacity / 10))
		frequency = 1;
	if ( (env->limit = (env->size_listsend / frequency) * 10) < 100)
		env->limit = 100;
	if ( !(env->recv_packet_max = env->process_capacity / 10) )
		env->recv_packet_max = 1;
	env->pck_max_ref = env->recv_packet_max;
	if (env->debug) {printf("Capacity: %d packet(s)/sec\n\n", env->recv_packet_max * 10);}
	env->prep_done = true;
}

void *send_th(void *arg)
{
	t_env *env;


	env = (t_env *)arg;
	pthread_mutex_lock(&env->mtx_wait);

	pre_send(env);
	while (1)
	{
		if (env->g_end == 1)
			return (NULL);
		send_batch(env);
		process_and_timeout(env);
	}
}
