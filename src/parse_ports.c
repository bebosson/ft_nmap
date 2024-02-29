#include "parse_ports.h"

#include "set_env.h"


static void get_bounds(int *min, int *max, int port)
{
	if (port < *min)
		*min = port;
	if (port > *max)
		*max = port;
}

static int get_list_from_port(char *port, char *dash, int *min, int *max, t_probe **list_head, bool parsing_ok)
{
	int ibound_min;
	int ibound_max;
	int i;
	int range;

	i = -1;
	dash = ft_strchr(port, '-');
	if (ft_strrnumeric(port, '-') && ft_str_is_numeric(dash + 1))
	{
		ibound_min = ft_atoi(port);
		ibound_max = ft_atoi(dash + 1);
		if (ibound_min > ibound_max)
			return (0);
		get_bounds(min, max, ibound_min);
		get_bounds(min, max, ibound_max);
		range = ibound_max - ibound_min;
		if (parsing_ok)
			while (++i <= range)
				*list_head = add_port_list(i + ibound_min, *list_head);
		return (1);
	}
	else
		return (0);
}

static int set_ports_bounds(char *port, char *dash, int *min, int *max, t_probe **list_head, bool parsing_ok)
{
	char *port_tmp;
	int	 ret;

	if (dash == port) //-22
	{
		if(!(port_tmp = ft_strjoin(STR_PORT_MIN, port)))
			return (0);
		ret = get_list_from_port(port_tmp, dash, min, max, list_head, parsing_ok);
		free(port_tmp);
		return (ret);
	}
	else if (dash == (port + ft_strlen(port) - 1)) //10-
	{
		if(!(port_tmp = ft_strjoin(port, STR_PORT_MAX)))
			return (0);
		ret = get_list_from_port(port_tmp, dash, min, max, list_head, parsing_ok);
		free(port_tmp);
		return (ret);
	}
	return (get_list_from_port(port, dash, min, max, list_head, parsing_ok));

}

int	sort_list(t_probe *list)
{
	t_probe *tmp = list;
	t_probe *next;
	uint16_t swap;
	int flag_troll = 0;

	while (tmp->next)
	{
		if (tmp->port_dst == tmp->next->port_dst)
		{
			flag_troll = 1;
			next = tmp->next->next;
			free(tmp->next);
			tmp->next = next;
		}
		else if (tmp->port_dst > tmp->next->port_dst)
		{
			swap = tmp->port_dst;
			tmp->port_dst = tmp->next->port_dst;
			tmp->next->port_dst = swap;
			tmp = list;
		}
		else
			tmp = tmp->next;
	}
	return (flag_troll);
}

int		probe_to_int(t_env *env, t_probe *probe_list)
{
	t_probe *tmp_probe;

	env->scanned_ports_len = 0;
	tmp_probe = probe_list;
	while (tmp_probe)
	{
		env->scanned_ports_len++;
		tmp_probe = tmp_probe->next;
	}
	if ( !(env->scanned_ports = ft_memalloc(sizeof(int) * env->scanned_ports_len + 1)))
		return (0);
	int i = 0;
	while (probe_list)
	{
		env->scanned_ports[i] = probe_list->port_dst;
		i++;
		probe_list = probe_list->next;
	}
	env->scanned_ports[i] = -1;
	return (1);
}
void	free_allport(int i, char **all_ports)
{
	free(all_ports[i]);
	while (all_ports[++i])
		free(all_ports[i]);
	free(all_ports);
}


int split_ports(char *port, t_env *env, bool parsing_ok)
{
	char *comma;
	char *dash;
	int i;
	char **all_ports;
	int min = 65535, max=0;
	int range;
	t_probe *list_base, *list_head;

	i = -1;
	if (parsing_ok)
	{
		if (! (list_base = ft_memalloc(sizeof(t_probe))))
			return (0);
		list_base->typescan = -1;
	}
	else
		list_base = NULL;
	list_head = list_base;
	if ( (comma = ft_strchr(port, ',')) == port)
		return (0);
	else 
	{
		all_ports = ft_strsplit(port, ',');
		while (all_ports[++i])
		{
			if ( (dash = ft_strchr(all_ports[i], '-')))
			{
				if(!(set_ports_bounds(all_ports[i], dash, &min, &max, &list_head, parsing_ok)))
				{
					free_allport(i, all_ports);
					return (0);
				}
			}
			else
			{
				if (!ft_str_is_numeric(all_ports[i]))
				{
					free_allport(i, all_ports);
					return (0);
				}
				get_bounds(&min, &max, ft_atoi(all_ports[i]));
				if (parsing_ok)
				{
					if(!(list_head = add_port_list(ft_atoi(all_ports[i]), list_head)))
						return (0);
				}
			}
			free(all_ports[i]);
		}
		free(all_ports);
		if (min < PORT_MIN || max > PORT_MAX)
			return (0);
		i = 0;
		range = max - min + 1; //range U , T
		if (!parsing_ok)
			return (1);
		env->flag_troll = sort_list(list_base);
		if (!(probe_to_int(env, list_base)))
			return (0);
		if (!(set_scantab(range, min, list_base, env)))
			return (0);
	}
	return (1);

}

int is_valid_ports(char **av, int ac)
{
	int i;

	i = 0;
	while (++i < ac - 1)
	{
		if (ft_strequ(av[i], "-p") && i + 1 < ac && !ft_strchr(av[i + 1], '.'))
			return (i + 1);
	}
	return (0);
}
