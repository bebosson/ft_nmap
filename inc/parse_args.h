#ifndef PARSE_ARGS_H
# define PARSE_ARGS_H

#include "ft_nmap.h"


t_parsline	*parse_and_save_node(int nbr, char **words, int start);
int looking_for_file(int ac, char **av);
t_parsline	*file_to_list(int fd);
t_env *save_parser(t_parsline *node, bool first_loop);
t_parsline	*pre_env(int ac, char **av);

# endif
