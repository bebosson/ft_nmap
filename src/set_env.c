#include "set_env.h"

#include "set_header.h"


int open_sendsocket(t_env *env)
{
	env->send_sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(env->send_sockfd == -1)
	{
		perror("Failed to create socket");
		return (0);
	}
	return (1);

}

t_probe *cpy_list(t_probe *list_src)
{
	t_probe *list_base;
	t_probe *cpy_list;
	t_probe *cpy_listnxt;

	if (! (cpy_list = ft_memalloc(sizeof(t_probe))))
		return (NULL);
	ft_memcpy(cpy_list, list_src, sizeof(t_probe));
	list_base = cpy_list;
	while (list_src->next)
	{
		if (! (cpy_listnxt = ft_memalloc(sizeof(t_probe))))
			return (NULL);
		ft_memcpy(cpy_listnxt, list_src->next, sizeof(t_probe));
		list_src = list_src->next;
		cpy_list->next = cpy_listnxt;
		cpy_list = cpy_list->next;
	}
	cpy_list->next = NULL;
	return (list_base);
}


	long int
ft_rand(void)
{
	struct timeval a, b;
	unsigned int mod, mul, inc;
	static unsigned int seed;

	gettimeofday(&a, NULL);
	gettimeofday(&b, NULL);
	mod = 65429;
	mul = a.tv_usec;
	inc = b.tv_usec;
	seed +=1;
	seed = (mul * seed + inc) % mod;
	return seed;
}

t_port *list_to_tabport(t_probe **base, int range, int min, int i, t_env *env)
{
	t_port *tab;
	t_probe *cpy;
	t_probe *prev;
	int cnt = 0;

	if (!(tab = ft_memalloc(sizeof(t_port) * range)))
		return (0);
	ft_memset(tab, 0, sizeof(tab));
	cpy = *base;
	prev = *base;
	while (cpy)
	{
		tab[cpy->port_dst - min].port_state = PORT_TO_SCAN;
		tab[cpy->port_dst - min].tries = 0;
		env->scantab[i].nb_port++;
		cpy = cpy->next;
		if (cnt)
			prev = prev->next;
		cnt++;
	}
	return (tab);
}

t_probe *fill_scan_list(t_probe *list_src, int8_t typescan, uint16_t portscan)
{
	t_probe *list_base;
	t_probe *cpy_list;
	t_probe *cpy_listnxt;
	uint16_t port_extended;

	port_extended = portscan;
	if (! (cpy_list = ft_memalloc(sizeof(t_probe))))
		return (NULL);
	ft_memcpy(cpy_list, list_src, sizeof(t_probe));
	cpy_list->typescan = typescan;
	cpy_list->port_src = portscan;
	list_base = cpy_list;
	while (list_src->next)
	{
		if (! (cpy_listnxt = ft_memalloc(sizeof(t_probe))))
			return (NULL);
		ft_memcpy(cpy_listnxt, list_src->next, sizeof(t_probe));
		cpy_listnxt->typescan = typescan;
		if (typescan & SCAN_UDP)
		{
			if ( (port_extended += 1) - portscan == 100)
				port_extended = portscan;
			cpy_listnxt->port_src = port_extended;
		}
		else
			cpy_listnxt->port_src = portscan;
		cpy_listnxt->prev = cpy_list;
		list_src = list_src->next;
		cpy_list->next = cpy_listnxt;
		cpy_list = cpy_list->next;
	}
	return (list_base);
}

void make_list_global(t_env *env)
{
	int i;
	t_probe *listprobe_head;

	i = 0;
	env->size_listsend = 1;
	listprobe_head = env->scantab[i].listprobe;
	env->listsend = listprobe_head;
	while (i < env->nb_scan)
	{
		listprobe_head = env->scantab[i].listprobe;
		while (listprobe_head->next) {
			env->size_listsend++;
			listprobe_head = listprobe_head->next;
		}
		if (i + 1 < env->nb_scan) {
			listprobe_head->next = env->scantab[i + 1].listprobe;
			env->scantab[i + 1].listprobe->prev = listprobe_head;
			env->size_listsend++;
			listprobe_head = listprobe_head->next;
		}
		else
			listprobe_head->next = NULL;
		i++;
	}
	env->listsend_head = listprobe_head;
}

int    print_list(t_usercv *listprobe)
{
	t_usercv *cpy;
	int i = 0;

	cpy = listprobe;
	while (cpy)
	{
		cpy = cpy->next;
		i++;
	}
	return (i);
}

void    setheader(t_probe *probe, void **header)
{
	if (probe->typescan == SCAN_SYN)
		set_tcp_syn_header(header, probe->port_src, probe->port_dst);
	else if (probe->typescan == SCAN_ACK)
		set_tcp_ack_header(header, probe->port_src, probe->port_dst);
	else if (probe->typescan == SCAN_NULL)
		set_tcp_null_header(header, probe->port_src, probe->port_dst);
	else if (probe->typescan == SCAN_FIN)
		set_tcp_fin_header(header, probe->port_src, probe->port_dst);
	else if (probe->typescan == SCAN_XMAS)
		set_tcp_xmas_header(header, probe->port_src, probe->port_dst);
	else if (probe->typescan == SCAN_UDP)
		set_udp_header(header, probe->port_src, probe->port_dst);
	else
		return ;
}

void	free_listbase(t_probe *listbase)
{
	t_probe *next;

	while (listbase)
	{
		next = listbase->next;
		free(listbase);
		listbase = next;
	}
}

int     set_scantab(int range, int min, t_probe *list_base, t_env *env)
{
	int i;
	uint32_t j;
	uint8_t bit_scan;

	i = 0;
	if (!(env->scantab = ft_memalloc(env->nb_scan * sizeof(t_scan))))
		return (0);
	j = 1;
	bit_scan = *(uint8_t*)&(env->scanfield);
	while (j < 64)
	{
		if (j & bit_scan) {
			if(!(env->scantab[i].tabport = list_to_tabport(&list_base, range, min, i, env)))
				return(0);
			env->scantab[i].min = min;
			env->scantab[i].range_port = range;
			env->scantab[i].scan_type = *(t_scanbits*)&j;
			if (env->debug){printf("portscan[%d] = %d\n", i, env->portscan[i]);}
			env->scantab[i].listprobe = fill_scan_list(list_base, j , env->portscan[i]);
			i++;
		}
		j <<= 1;
	}
	free_listbase(list_base);
	return (1);
}

t_probe    *add_port_list(int inewport, t_probe *head)
{
	t_probe *newport;

	if (head) 
	{
		if (head->typescan < 0)
		{
			head->typescan = 0;
			head->port_dst = inewport;
			return (head);
		}
		else
		{
			if (! (newport = ft_memalloc(sizeof(t_probe))))
				return (NULL);
			newport->port_dst = inewport;
			head->next = newport;
			return (head->next); //newport
		}
	}
	return (NULL);
}

uint16_t *create_portscan(int nb_scan, t_scanbits scanfield, uint16_t *port_max)
{
	uint16_t *portscan;
	uint8_t bit_scan;
	uint16_t port_first = ft_rand();
	int i;
	int j;

	i = 0;
	j = 1;
	if (!(portscan = ft_memalloc(sizeof(uint16_t) * nb_scan)))
		return (0);
	bit_scan = *(uint8_t*)&(scanfield);
	while (j < 64)
	{
		if (j & bit_scan)
		{
			portscan[i] = port_first++;
			i++;
		}
		j <<= 1;
	}
	*port_max = port_first - 1;
	return (portscan);
}
