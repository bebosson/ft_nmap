#ifndef DISPLAY_RESULT_H
# define DISPLAY_RESULT_H

# include "ft_nmap.h"


void	write_the_scan(t_env *env, int fd);
void	pre_scan_display(t_env *env, int fd);
void	get_day_and_time(struct timeval *tv);
char	*print_scan(int scan);
char *print_ipproto(int protocol);
int print_tcp_pkt(struct iphdr *ip, struct tcphdr *tcp);
int print_tcp_icmp_pkt(struct iphdr *ip, struct icmphdr *icmp, struct tcphdr *tcp);
int print_udp_pkt(struct iphdr *ip, struct udphdr *udp);
int print_udp_icmp_pkt(struct iphdr *ip, struct icmphdr *icmp, struct udphdr *udp);


# endif
