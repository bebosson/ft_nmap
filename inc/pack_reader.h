#ifndef PACK_READER_H
# define PACK_READER_H

# include "ft_nmap.h"


void    *pkt_reader(void *env);
void	process_and_timeout(t_env *env);
void	*process_th(void *arg);
int8_t	process_pkt(t_env *env);

# endif
