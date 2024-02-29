#ifndef PARSE_PORTS_H
#define PARSE_PORTS_H

#include "ft_nmap.h"


#define STR_PORT_MIN "1"
#define STR_PORT_MAX "65535"
#define PORT_MIN 0
#define PORT_MAX 65535


int is_valid_ports(char **av, int ac);
int split_ports(char *port, t_env *env, bool parsing_ok);

#endif
