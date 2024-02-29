#ifndef EXEC_H
#define EXEC_H

#include "ft_nmap.h"


typedef struct s_timeout_env
{
	int fd;
	struct in_addr dev_addr;
	uint16_t port;
	bool *retry_flag;
} t_timeout_env;

extern t_timeout_env g_timeout_env;

int		exec_nmap(t_env *env);

#endif 
