#include "parse_args.h"

#include "parse_addr.h"
#include "parse_scan.h"
#include "parse_ports.h"
#include "set_env.h"
#include "set_pcap.h"
#include "get_next_line.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


static int	parse_for_help(int ac, char **av, int i)
{
	char *str = "Help Screen \n\
ft_nmap [OPTIONS] \n\
--help Print this help screen \n\
--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15) \n\
--ip ip addresses to scan in dot format \n\
--file File name containing IP addresses to scan, \n\
--speedup [250 max] number of parallel threads to use \n\
--scan SYN/NULL/FIN/XMAS/ACK/UDP\n\
For more precisions, please read the README\n";
	while (++i < ac)
	{
		if (ft_strequ(av[i], "--help") || ft_strequ(av[i], "-h"))
		{
			printf("%s\n", str);
			return(1);
		}
	}
	return (0);
}

int		parse_args_for_addr(int ac, char **av, int i)
{
	while(++i < ac)
	{
		if (i > 0 && (ft_strequ(av[i -1], "-p") || ft_strequ(av[i -1], "-t")))
			continue;
		else if (reverse_addr(NULL, av[i], 0)) 
			return (i);
	}
	return (-1);
}

int is_th_precised(int ac, char **av, int i, bool *th_precised)
{
	int th;
	*th_precised = false;

	while (++i < ac - 1)
	{
		if (av[i + 1] && ft_strequ(av[i], "-t") && ft_str_is_numeric(av[i + 1]))
		{
			th = ft_atoi(av[i + 1]);
			if (th > 0 && th <= 250)
			{
				*th_precised = true;
				return (th);
			}
		}
		else if (th <= 0 || th > 250 || !av[i + 1])
		{
			printf("error parsing: nb of threads needs to be explicit, positive and under or equal to 250\n");
			return (-1);
		}
	}
	return (1);
}

static int count_args(int ac, int addr, int port_index, int scan_index, bool thread, bool *debug)
{
	int i = 0;

	if (addr > 0)
		i++;
	if (port_index > 0)
		i+=2;
	if (scan_index > 1)
		i+=2;
	if (thread)
		i+=2;
	if (*debug)
		i++;
	if (ac != i + 1)
	{
		printf("ERROR_PARSING\n");
		return (0);
	}
	else
		return (1);
}

static void parse_for_debug(int ac, char **av, int i, bool *debug)
{
	while (++i < ac)
	{
		if (ft_strequ(av[i], "--debug"))
		{
			*debug = 1;
			return ;
		}
	}
	return ;
}

static int		is_all_parsing_ok(int ac, char **av, int start, int *addr, int *port_index, int *thread, bool *debug)
{
	int ret;
	int scan_index;
	bool thread_precise;

	thread_precise = false;
	parse_for_debug(ac, av, start, debug);
	if (parse_for_help(ac, av, 0))
		return (-1);
	if ((*addr = parse_args_for_addr(ac, av, start)) < 0)
	{
		printf("error addr: no addr precised \n");
		return (-1);
	}
	if ((ret = parse_args_for_addr(ac, av, *addr)) > 0)
	{
		printf("error addr: 2 addr precised %d\n", ret);
		return (-1);
	} 
	if (!(scan_index = is_scan_precised(av, ac, NULL, 0)))
	{
		printf("SCAN FAIL\n");
		return (-1);
	}
	if ((*thread = is_th_precised(ac, av, start, &thread_precise)) < 0)
	{
		printf("THREAD FAIL\n");
		return (-1);
	}
	if ((*port_index = is_valid_ports(av, ac)) && !split_ports(av[*port_index], NULL, 0)) // -p XX,XY-YY,....
	{
		printf("PORT FAIL\n");
		return (-1);
	}
	else 
	{
		if (!count_args(ac, *addr, *port_index, scan_index, thread_precise, debug))
			return (-1);
		else
			return (1);
	}
}

t_parsline	*parse_and_save_node(int nbr, char **words, int start)
{
	int 	addr;
	int 	port_index;
	t_parsline	*node;
	int thread = 0;
	bool debug = false;


	if (is_all_parsing_ok(nbr, words, start, &addr, &port_index, &thread, &debug) > 0) //for file
	{
		if (!(node = ft_memalloc(sizeof(t_parsline))))
			return (NULL);
		node->av = words;
		node->ac = nbr;
		node->addr = addr;
		node->port_index = port_index;
		node->thread = thread;
		if (debug)
		node->debug = true;
		return node;
	}
	else
		return (0);
}

static t_parsline	*parser(char *line)
{
	char 	**words;
	int		nbr;
	t_parsline	*node;

	nbr = -1;
	if (!(words = ft_strsplit(line, ' ')))
		return (NULL);
	while (words[++nbr])
		;
	if (nbr > 0 && (node = parse_and_save_node(nbr, words, -1)))
	{
		node->file = 1;
		return (node);
	}
	nbr = -1;
	while (words[++nbr])
		free(words[nbr]);
	free(words);
	return (0);
}

int looking_for_file(int ac, char **av)
{
	int i;
	i = 0;

	while (++i < ac - 1)
	{
		if (ft_strequ(av[i], "-f") && av[i + 1])
			return (i + 1);
	}
	return (0);
}

t_env *save_parser(t_parsline *node, bool first_loop)
{
	t_env *env;

	if(!(env = malloc(sizeof(t_env))))
		return (0);
	ft_memset(env, 0, sizeof(t_env));
	env->fd_result =  fileno(fopen("result.txt", "a+"));
	env->debug = node->debug;
	if (!get_addr(env, node->av[node->addr]))
	{
		printf("error addr: no addr precised \n");
		exit(EXIT_FAILURE);
	}
	if (!is_scan_precised(node->av, node->ac, env, 1))
	{
		printf("SCAN FAIL\n");
		free(env->pars->buf_addr);
		free(env->pars);
		free(node);
		free(env);
		return (0);
	}
	if(!(env->portscan = create_portscan(env->nb_scan, env->scanfield, &env->port_max)))
		return (0);
	if ((node->port_index && split_ports(node->av[node->port_index], env, 1) == 0) 
			|| (!node->port_index && split_ports("1-1024", env, 1) == 0))
	{
		printf("error port \n");
		exit(EXIT_FAILURE);
	}
	make_list_global(env);
	if (!(open_sendsocket(env)))
		printf("ERROR SOCKET\n");
	env->total = node->thread;
	if (env->size_listsend < env->total)
		env->total = env->size_listsend + 1;
	env->nbprocess_th = env->total - 2;

	env->tick_count = 0;
	env->randport_timeout = ft_rand();
	if (!ft_pcap_init(env))
		return (NULL);
	pthread_mutex_init(&env->mtx_toprocess, NULL);
	pthread_mutex_init(&env->mtx_wait, NULL);
	pthread_mutex_init(&env->mtx_debug, NULL);
	env->sendback = NULL;
	env->sendback_head = NULL;
	env->toprocess = NULL;
	env->toprocess_head = NULL;
	env->retry_flag = 0;
	env->g_end = 0;
	env->first_loop = first_loop;
	env->process_capacity = 100;
	env->prep_done = false;
	ft_memset(&env->tv_retry, 0, sizeof(struct timeval));
	env->sending_pair = NULL;
	env->first_pkt_arrived = false;
	if (env->total > 1)
		env->testing_pair = init_sending_pair();
	env->timeout_usec = 100000;
	pthread_mutex_init(&env->mtx_recv, NULL);
	pthread_mutex_init(&env->mtx_recv_cnt, NULL);
	env->recv_cnt = 0;
	env->recv_reachcnt = 0;
	env->tries = 1;
	return (env);
}

int tricky_file(char *av)
{
	if (!ft_strcmp(av, "/dev/zero") || ft_strstr(av, "/dev/tty"))
		return (0);
	else
		return (1);
}

t_parsline	*pre_env(int ac, char **av)
{
	int index;
	FILE *stream;
	int fd;
	t_parsline	*args_tab;

	if ( (index = looking_for_file(ac, av)) > 0)
	{
		if (ac != 3)
			return (NULL);
		if ( !tricky_file(av[index]))
			return (NULL);
		if ( !(stream = fopen(av[index], "r+")))
		{
			printf("error file\n");
			return (NULL);
		}
		if ( !(fd = fileno(stream)))
			return (NULL);
		if ( !(args_tab = file_to_list(fd)))
			return (NULL);
		fclose(stream);
	}
	else
	{
		if ( !(args_tab = parse_and_save_node(ac, av, 0)))
			return (NULL);
		args_tab->file = 0;
	}
	if ( !(stream = fopen("result.txt", "w+")))
		return (NULL);
	if (fclose(stream) == EOF)
		return (NULL);
	return (args_tab);
}

t_parsline	*file_to_list(int fd_file)
{
	char *line;
	t_parsline	*head;
	t_parsline	*base;

	if (get_next_line(fd_file, &line))
	{
		if ( !(base = parser(line)))
		{
			free(line);
			return (0);
		}
		head = base;
		free(line);
	}
	else
	{
		printf("File is empty\n");
		return (0);
	}
	while (get_next_line(fd_file, &line))
	{
		if ( (head->next = parser(line)))
			head = head->next;
		free(line);
	}
	return (base);
}
