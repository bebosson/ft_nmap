#include "parse_scan.h"


static void all_scan_default(t_env *env)
{
	env->scanfield.SYN = 1;
	env->scanfield.ACK = 1;
	env->scanfield.NUL = 1;
	env->scanfield.FIN = 1;
	env->scanfield.XMAS = 1;
	env->scanfield.UDP = 1;
	env->nb_scan = 6;
}

static int is_correct_scan(char *scan)
{
	if (ft_strequ(scan, "SYN")
			|| ft_strequ(scan, "ACK") 
			|| ft_strequ(scan, "NULL")
			|| ft_strequ(scan, "FIN")
	 		|| ft_strequ(scan, "XMAS")
	 		|| ft_strequ(scan, "UDP"))
		{
			free(scan);
			return (1);
		}
	free(scan);
	return (0);
}

static int is_valid_scan(char *scan, t_env *env)
{
	if(ft_strequ(scan, "SYN") && env->scanfield.SYN == 0)
		env->scanfield.SYN = 1;
	else if(ft_strequ(scan, "ACK") && env->scanfield.ACK == 0)
		env->scanfield.ACK = 1;
	else if(ft_strequ(scan, "NULL") && env->scanfield.NUL == 0)
		env->scanfield.NUL = 1;
	else if(ft_strequ(scan, "FIN") && env->scanfield.FIN == 0)
		env->scanfield.FIN = 1;
	else if(ft_strequ(scan, "XMAS") && env->scanfield.XMAS == 0)
		env->scanfield.XMAS = 1;
	else if(ft_strequ(scan, "UDP") && env->scanfield.UDP == 0)
		env->scanfield.UDP = 1;
	else
	{
		free(scan);
		return (0);
	}
	free(scan);
	return (1);
}


static int save_valid_scan(char *scan, t_env *env, bool parsing_ok)
{
	char **all_scan;
	int i;
	int save_scan;

	i = -1;

	if (!scan || scan[0] == ',' || scan[ft_strlen(scan) - 1] == ',')
		return (0);
	while (scan[++i])
	{
		if ((size_t)i + 1 < ft_strlen(scan))
			if (scan[i] == ',' && scan[i + 1] == ',')
				return (0);
	}
	if(!(all_scan = ft_strsplit(scan, ',')))
		return (0);
	i = -1;
	while (all_scan[++i])
	{
		if(parsing_ok)
		{
			if (!(save_scan = is_valid_scan(all_scan[i], env)))
			{
				while (all_scan[++i])
					free(all_scan[i]);
				free(all_scan);
				return (0);
			}
			env->nb_scan++;
		}
		else if (!(save_scan = is_correct_scan(all_scan[i])))
		{
			while (all_scan[++i])
				free(all_scan[i]);
			free(all_scan);
			return (0);
		}
	}
	free(all_scan);
	return (1);
}

int is_scan_precised(char **av, int ac, t_env *env, bool parsing_ok)
{
	int i;

	i = 0;
	if (parsing_ok)
		ft_memset(&(env->scanfield), 0, sizeof(t_scanbits));
	while(++i < ac - 1)
	{
		if (ft_strequ(av[i], "-s") && i + 1 < ac)
		{
			if (save_valid_scan(av[i + 1], env, parsing_ok))
			{
				return (i + 1);
			}
			else
				return (0);
		}
	}
	i = 0;
	while (++i < ac - 1)
		if (save_valid_scan(av[i + 1], env, parsing_ok))
			return (0);
	if (parsing_ok)
		all_scan_default(env);
	return (1);
}
