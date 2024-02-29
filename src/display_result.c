#include "display_result.h"

#include "ft_nmap.h"


static char *which_flags(int bit_scan)
{
	int i = 0;
	int bit = 1;
	const char *scan[] = {" SYN"," ACK", " NULL", " FIN", " XMAS", " UDP"};
	char *base = NULL;
	char *base_tmp;
	while (bit <= 32)
	{
		if (bit & bit_scan)
		{
			if (!base)
				base = ft_strdup(scan[i]);
			else
			{
				base_tmp = base;
				base = ft_strjoin(base_tmp, scan[i]);
				free(base_tmp);
			}
		}
		bit <<= 1;
		i++;
	}
	return (base);
}

void	pre_scan_display(t_env *env, int fd)
{
	uint16_t bit_scan;
	char *flags;

	bit_scan = *(uint16_t *)&env->scanfield;
	flags = which_flags(bit_scan);
	if (fd == env->fd_result)
		dprintf(env->fd_result, "Results for %s\n", env->pars->buf_addr);
	dprintf(fd,"\nScan configurations\n\
No of ports to scan: %d\n\
Scans to be performed:%s\n\
No of threads: %d\n",
			env->scanned_ports_len, flags, env->total);
	free(flags);
}

void	get_day_and_time(struct timeval *tv)
{
	// Compute the number of days since the epoch
	long int days_since_epoch = tv->tv_sec / 86400; // 86400 seconds per day

	// Compute the year, month, and day
	long int years_since_epoch = days_since_epoch / 365;
	int current_year = 1970 + years_since_epoch;
	int leap_years = (current_year - 1968) / 4 - (current_year - 1900) / 100 + (current_year - 1600) / 400;
	int days_in_year = days_since_epoch - (years_since_epoch * 365 + leap_years);
	int current_month = 0;
	int days_in_month;

	while (days_in_year >= 0) {
		days_in_month = 31;
		if (current_month == 1) {
			days_in_month = ((current_year % 4 == 0 && current_year % 100 != 0) || current_year % 400 == 0) ? 29 : 28;
		} else if (current_month == 3 || current_month == 5 || current_month == 8 || current_month == 10) {
			days_in_month = 30;
		}
		days_in_year -= days_in_month;
		current_month++;
	}
	current_month--;

	int current_day = days_in_year + days_in_month + 1;

	// Compute the hour, minute, and second
	int current_hour = (tv->tv_sec / 3600) % 24 + 2; // 3600 seconds per hour
	int current_minute = (tv->tv_sec / 60) % 60; // 60 seconds per minute
	int current_second = tv->tv_sec % 60;

	// Print the current date and time
	printf("Starting ft_nmap at %04d-%02d-%02d %02d:%02d:%02d\n",
			current_year, current_month + 1, current_day, current_hour, current_minute, current_second);
}

char	*print_scan(int scan)
{
	if (scan == SCAN_SYN)
		return ("scan: SYN\n");
	else if (scan == SCAN_ACK)
		return ("scan: ACK\n");
	else if (scan == SCAN_NULL)
		return ("scan: NULL\n");
	else if (scan == SCAN_FIN)
		return ("scan: FIN\n");
	else if (scan == SCAN_XMAS)
		return ("scan: XMAS\n");
	else if (scan == SCAN_UDP)
		return ("scan: UDP\n");
	else
		return ("ERROR ?\n");
}

char *print_ipproto(int protocol)
{
	if (protocol == IPPROTO_TCP)
		return ("TCP");
	if (protocol == IPPROTO_UDP)
		return ("UDP");
	if (protocol == IPPROTO_ICMP)
		return ("ICMP");
	return (NULL);
}

int print_tcp_pkt(struct iphdr *ip, struct tcphdr *tcp)
{
	char *saddr;
	char *daddr;
	char *tmp;
	int len;

	tmp = inet_ntoa(*(struct in_addr *)&ip->saddr);
	len = ft_strlen(tmp);
	if ( !(saddr = malloc(sizeof(char) * len + 1)))
		return (0);
	ft_memcpy(saddr, tmp, len);
	saddr[len] = '\0';
	tmp = inet_ntoa(*(struct in_addr *)&ip->daddr);
	len = ft_strlen(tmp);
	if ( !(daddr = malloc(sizeof(char) * len + 1)))
		return (0);
	ft_memcpy(daddr, tmp, len);
	daddr[len] = '\0';
	dprintf(2, "\n+........................................+\n\
IP:\nProtocol: %s (%d)\nSource address: %s\nDestination address: %s\n\
    ---------------------------------\n\
\tTCP:\n\tSource port: %d\n\tDestination port: %d\n\
\tFlags: FIN = %d\n%21s%d\n%21s%d\n%21s%d\n%21s%d\n%21s%d\n\
-........................................-\n",
		print_ipproto(ip->protocol), ip->protocol, saddr, daddr,
		htons(tcp->source), htons(tcp->dest),
		tcp->fin, "SYN = ", tcp->syn, "RST = ", tcp->rst,
		"PSH = ", tcp->psh, "ACK = ", tcp->ack, "URG = ", tcp->urg);
	free(saddr);
	free(daddr);
	return (1);
}

int print_tcp_icmp_pkt(struct iphdr *ip, struct icmphdr *icmp, struct tcphdr *tcp)
{
	char *saddr;
	char *daddr;
	char *tmp;
	int len;

	tmp = inet_ntoa(*(struct in_addr *)&ip->saddr);
	len = ft_strlen(tmp);
	if ( !(saddr = malloc(sizeof(char) * len + 1)))
		return (0);
	ft_memcpy(saddr, tmp, len);
	saddr[len] = '\0';
	tmp = inet_ntoa(*(struct in_addr *)&ip->daddr);
	len = ft_strlen(tmp);
	if ( !(daddr = malloc(sizeof(char) * len + 1)))
		return (0);
	ft_memcpy(daddr, tmp, len);
	daddr[len] = '\0';
	dprintf(2, "\n+.......................................+\n\
IP:\nProtocol: %s (%d)\nSource address: %s\nDestination address: %s\n\
    ---------------------------------\n\
\tICMP:\n\tType: %d\n\tCode: %d\n\
\t-----------------------------\n\
\t\tTCP:\n\t\tSource port: %d\n\t\tDestination port: %d\n\
\t\tFlags: FIN = %d\n%29s%d\n%29s%d\n%29s%d\n%29s%d\n%29s%d\n\
-........................................-\n",
		print_ipproto(ip->protocol), ip->protocol, saddr, daddr,
		icmp->type, icmp->code,
		htons(tcp->source), htons(tcp->dest),
		tcp->fin, "SYN = ", tcp->syn, "RST = ", tcp->rst,
		"PSH = ", tcp->psh, "ACK = ", tcp->ack, "URG = ", tcp->urg);
	free(saddr);
	free(daddr);
	return (1);
}

int print_udp_pkt(struct iphdr *ip, struct udphdr *udp)
{

	char *saddr;
	char *daddr;
	char *tmp;
	int len;

	tmp = inet_ntoa(*(struct in_addr *)&ip->saddr);
	len = ft_strlen(tmp);
	if ( !(saddr = malloc(sizeof(char) * len + 1)))
		return (0);
	ft_memcpy(saddr, tmp, len);
	saddr[len] = '\0';
	tmp = inet_ntoa(*(struct in_addr *)&ip->daddr);
	len = ft_strlen(tmp);
	if ( !(daddr = malloc(sizeof(char) * len + 1)))
		return (0);
	ft_memcpy(daddr, tmp, len);
	daddr[len] = '\0';
	dprintf(2, "\n+........................................+\n\
IP:\nProtocol: %s (%d)\nSource address: %s\nDestination address: %s\n\
    ---------------------------------\n\
\tUDP:\n\tSource Port: %d\n\tDestination Port: %d\n\
-........................................-\n",
		print_ipproto(ip->protocol), ip->protocol, saddr, daddr,
		ntohs(udp->uh_sport), ntohs(udp->uh_dport));
	free(saddr);
	free(daddr);
	return (1);
}

int print_udp_icmp_pkt(struct iphdr *ip, struct icmphdr *icmp, struct udphdr *udp)
{
	char *saddr;
	char *daddr;
	char *tmp;
	int len;

	tmp = inet_ntoa(*(struct in_addr *)&ip->saddr);
	len = ft_strlen(tmp);
	if ( !(saddr = malloc(sizeof(char) * len + 1)))
		return (0);
	ft_memcpy(saddr, tmp, len);
	saddr[len] = '\0';
	tmp = inet_ntoa(*(struct in_addr *)&ip->daddr);
	len = ft_strlen(tmp);
	if ( !(daddr = malloc(sizeof(char) * len + 1)))
		return (0);
	ft_memcpy(daddr, tmp, len);
	daddr[len] = '\0';
	dprintf(2, "\n+.......................................+\n\
IP:\nProtocol: %s (%d)\nSource address: %s\nDestination address: %s\n\
    ---------------------------------\n\
\tICMP:\n\tType: %d\n\tCode: %d\n\
\t-----------------------------\n\
\t\tUDP:\n\t\tSource Port: %d\n\t\tDestination Port: %d\n\
-.......................................-\n",
			print_ipproto(ip->protocol), ip->protocol, saddr, daddr,
			icmp->type, icmp->code, ntohs(udp->uh_sport), ntohs(udp->uh_dport));
	free(saddr);
	free(daddr);
	return (1);
}

static char    *print_result_port(t_port *tabport)
{
    switch (tabport->port_state)
    {
        case (PORT_OPEN): 
            return ("Open");
		break;
		case (PORT_CLOSE):
			return ("Closed");
        break;
		case (PORT_FILTER):
			return ("Filtered");
		break;
		case (PORT_UNFILTER):
			return ("Unfiltered");
		break;
		case (PORT_OPEN_FILTER):
			return ("Open|Filtered");
		break;
        default:
			return ("ERROR (?)");
        break;
    }
}

static int    print_scantype_and_result(int fd, uint16_t bitscan ,t_port *tabport)
{
	int len = ft_strlen(print_result_port(tabport));
    switch (bitscan)
    {
        case (SCAN_SYN):
			dprintf(fd, "SYN(%s)", print_result_port(tabport));
			len += 5;
			break ;
        case (SCAN_ACK):
			dprintf(fd, "ACK(%s)", print_result_port(tabport));
			len += 5;
			break ;
        case (SCAN_NULL):
			dprintf(fd, "NULL(%s)", print_result_port(tabport));
			len += 6;
			break ;
		case (SCAN_FIN):
			dprintf(fd, "FIN(%s)", print_result_port(tabport));
			len += 5;
			break;
        case (SCAN_XMAS):
			dprintf(fd, "XMAS(%s)", print_result_port(tabport));
			len += 6;
			break ;
        case (SCAN_UDP):
			dprintf(fd, "UDP(%s)", print_result_port(tabport));
			len += 5;
			break ;
		default: 
			dprintf(fd, "error?\n");
			len = 6;
    }
	return (len);
}

void	write_the_scan(t_env *env, int fd)
{
	int i;
	int bit;
	int port;
	uint16_t bit_scan;
	uint16_t min;
	t_port *tabport;
    struct servent *serv; 
	int len;


	port = 0;
	bit_scan = *(uint16_t *)&env->scanfield;
	dprintf(fd, "PORT    Service Name    Results\n");
	dprintf(fd, "--------------------------------------------------------------------\n");

	while (env->scanned_ports[port] >= 0)
	{
		i = 0;
		bit = 1;
		len = 0;
		dprintf(fd,"%-8d", env->scanned_ports[port]);
	 	serv = getservbyport(htons(env->scanned_ports[port]), NULL);
		if (serv && serv->s_name)
			dprintf(fd, "%-16s", serv->s_name);
		else
			dprintf(fd, "unknown%9s", "");
		while (bit <= 32)
		{
			if (bit & bit_scan)
			{
				min = env->scantab[i].min;
				tabport = &(env->scantab[i].tabport[env->scanned_ports[port] - min]);

				if (i == 3 || i == 5)
					dprintf(fd, "%-24s", "");
				len += print_scantype_and_result(fd, bit & bit_scan, tabport);
				if ((i == 0 || i == 1 || i == 3) && i + 1 != env->nb_scan)
				{
					dprintf(fd, "  ");
					len += 2;
				}
				else if (i + 1 != env->nb_scan)
				{
					dprintf(fd, "\n");
					len = 0;
				}
				i++;
			}
			bit <<= 1;
		}
		port++;
		dprintf(fd, "\n\n");
	}
}
