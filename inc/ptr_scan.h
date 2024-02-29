#ifndef PTR_SCAN_H
# define PTR_SCAN_H

# include "ft_nmap.h"


int	do_the_scan(uint16_t typescan, t_port *tabscan, t_usercv *packet, bool debug, pthread_mutex_t *mtx_debug);

#endif
