#ifndef SET_ENV_H
#define SET_ENV_H

#include "ft_nmap.h"


t_probe*	add_port_list(int inewport, t_probe *base);
int			set_scantab(int range, int min, t_probe *list_base, t_env *env);
int 		print_list(t_usercv *list_base);
void		make_list_global(t_env *env);
uint16_t	*create_portscan(int nb_scan, t_scanbits scanfield, uint16_t *port_max);
void		setheader(t_probe *probe, void **header);
long int	ft_rand(void);
t_probe     *copy_list(t_env *env);
t_probe     *cpy_list(t_probe *list_src);
int         open_sendsocket(t_env *env);

#endif
