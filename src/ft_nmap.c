#include "ft_nmap.h"

#include "parse_args.h"
#include "exec.h"
#include "send.h"
#include "display_result.h"


void exit_free(t_env *env)
{
	int i = -1;
	t_probe *next;

	while (++i < env->nb_scan)
	{
		free(&env->portscan[i]);
		while (env->scantab[i].listprobe)
		{
			next = env->scantab[i].listprobe->next;
			free(env->scantab[i].listprobe);
			env->scantab[i].listprobe = next;
		}
		free(env->scantab[i].tabport);
	}
	free(env->scanned_ports);
	free(env->scantab);
	free(env->pars->buf_addr);
	free(env->pars);
	free(env);
	exit(EXIT_FAILURE);
}

void	free_env(t_env *env)
{
	int i;

	i = -1;

	free(env->scanned_ports);
	free(env->pars->buf_addr);
	free(env->pars);
	while(++i < env->nb_scan)
	{
		free(env->scantab[i].tabport);
	}
	free(env->scantab);
	free(env->portscan);
	pcap_close(env->handle);
	if (env->toprocess)
	{
		t_usercv *node;
		t_usercv *next;

		node = env->toprocess;
		while (node)
		{
			next = node->next;
			free(node);
			node = next;
		}
	}
	free(env);

}


void	free_scantab(t_env *env)
{
	t_probe *next;
	t_probe *listprobe;

	int i = -1;
	while (++i < env->nb_scan)
	{
		listprobe = env->scantab[i].listprobe;
		while (listprobe)
		{
			next = listprobe->next;
			free(listprobe);
			listprobe = next;
		}
	}
}

void	free_arg_tabs(t_parsline *arg_tabs)
{
	int i = -1;

	if (arg_tabs->file == 1)
	{
		while (arg_tabs->av[++i])
			free(arg_tabs->av[i]);
		free(arg_tabs->av);
	}
	free(arg_tabs);
}

int     main(int ac, char **av)
{
	t_env *env;
	struct timeval tv_start;
	struct timeval tv_end;
	t_parsline	*args_tab;
	t_parsline	*next;
	bool first_loop = true;
	int nb_ip = 0;

	gettimeofday(&tv_start, NULL);
	get_day_and_time(&tv_start);
	if ( !(args_tab = pre_env(ac, av)))
		return (-1);
	while (args_tab)
	{
		if ( !(env = save_parser(args_tab, first_loop)))
			return (-1);
		if (env->flag_troll)
			printf("WARNING: Duplicate port number(s) specified. Are you alert enough to be using ft_nmap?\n");
		printf("ft_nmap scan report for %s (%s)\n", args_tab->av[args_tab->addr], env->pars->buf_addr);
		if (!exec_nmap(env))
		{
			free_arg_tabs(args_tab);
			free_env(env);
		}
		if (first_loop == true)
			first_loop = false;
		next = args_tab->next;
		free_arg_tabs(args_tab);
		args_tab = next;
		pre_scan_display(env, env->fd_result);
		write_the_scan(env, env->fd_result);
		pre_scan_display(env, 1);
		write_the_scan(env, 1);
		free_env(env);
		nb_ip++;
	}
	gettimeofday(&tv_end, NULL);
	tvsub(&tv_end, &tv_start);
	dprintf(1, "ft_nmap done: %d IP %s scanned in %ld.%.2lds\n", nb_ip, nb_ip == 1 ? "address" : "addresses",tv_end.tv_sec, tv_end.tv_usec / 10000);
	return (0);
}
