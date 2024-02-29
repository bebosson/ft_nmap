#ifndef PARSE_ADDR_H
#define PARSE_ADDR_H

#include "ft_nmap.h"


#define SERV_PORT_TCP 4000 


int get_addr(t_env *env, char *argv);
int reverse_addr(t_env *env, char *addr, bool parsing_ok);
#endif
