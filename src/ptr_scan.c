#include "ptr_scan.h"
#include "ft_nmap.h"

#include "display_result.h"

static int scan_tcp_icmp(t_usercv *packet, bool debug)
{
	struct icmphdr *icmp;

	icmp = (struct icmphdr *)(packet->user + sizeof(struct iphdr) + sizeof(struct ether_header) + 2);
	if (icmp->code == 3 && (icmp->type == 1 || icmp->type == 2 || icmp->type == 9 || icmp->type == 10 || icmp->type == 13))
	{
		if (debug)
		{
			struct iphdr *ip;
			struct tcphdr *tcp;

			ip = (struct iphdr *)(packet->user + sizeof(struct ether_header) + 2);
			tcp = (struct tcphdr *)(packet->user + sizeof(struct iphdr) + sizeof(struct ether_header) + 2 + sizeof(struct icmphdr) + sizeof(struct iphdr));
			return (print_tcp_icmp_pkt(ip, icmp, tcp));
		}
	}
	return (-1);
}

static int read_syn_packet_tcp(t_usercv *packet)
{
	struct tcphdr *tcp;

	tcp = (struct tcphdr *)(packet->user + sizeof(struct ip) + sizeof(struct ether_header) + 2);
	if (tcp->syn == 1 && tcp->ack == 1)
		return (1);
	else if (tcp->rst == 1)
		return (2);
	else
		return (3);
}

static int syn_scan(t_port *tabscan, t_usercv *packet, bool debug, bool error)
{
	int ret = 1;

	if (!packet)
	{
		if (tabscan->tries == 2)
			tabscan->port_state = PORT_FILTER;
	}
	else if (error == true && (ret = scan_tcp_icmp(packet, debug) > 0))
		tabscan->port_state = PORT_FILTER;
	else if (!ret)
		return (0);
	else if ( (ret = read_syn_packet_tcp(packet)) == 1)
		tabscan->port_state = PORT_OPEN;
	else if (ret == 2)
		tabscan->port_state = PORT_CLOSE;
	return (ret);
}

static int ack_scan(t_port *tabscan, t_usercv *packet, bool debug, bool error)
{
	struct tcphdr *tcp;
	int ret = 1;

	if (!packet)
	{
		if (tabscan->tries == 2)
			tabscan->port_state = PORT_FILTER;
		return (1);
	}
	tcp = (struct tcphdr *)(packet->user + sizeof(struct ip) + sizeof(struct ether_header) + 2);

	if (error == true && (ret = scan_tcp_icmp(packet, debug)))
		tabscan->port_state = PORT_FILTER;
	if (!ret)
		return (0);
	else if (tcp->rst == 1)
		tabscan->port_state = PORT_UNFILTER;
	return (ret);
}

static int fin_null_xmas_scan(t_port *tabscan, t_usercv *packet, bool debug, bool error)
{
	struct tcphdr *tcp;
	int ret = 1;

	if (!packet)
	{
		if (tabscan->tries == 2)
			tabscan->port_state = PORT_OPEN_FILTER;
		return (1);
	}
	tcp = (struct tcphdr *)((char *)packet->user + sizeof(struct ip) + sizeof(struct ether_header) + 2);

	if (error == true && (ret = scan_tcp_icmp(packet, debug)))
		tabscan->port_state = PORT_FILTER;
	if (!ret)
		return (0);
	else if (tcp->rst == 1)
		tabscan->port_state = PORT_CLOSE;
	return (ret);
}

static int tcp_scan(uint16_t typescan, t_port *tabscan, t_usercv *packet, bool debug, pthread_mutex_t *mtx_debug)
{
	bool error = false;
	int ret;

	if (packet)
	{
		struct iphdr *ip;

		ip = (struct iphdr *)(packet->user + sizeof(struct ether_header) + 2);
		if (ip->protocol == IPPROTO_ICMP)
			error = true;
		if (error == false && debug)
		{
			struct tcphdr *tcp;

			tcp = (struct tcphdr *)((char *)packet->user + sizeof(struct ip) + sizeof(struct ether_header) + 2);
			pthread_mutex_lock(mtx_debug);
			ret = print_tcp_pkt(ip, tcp);
			pthread_mutex_unlock(mtx_debug);
			if (!ret)
				return (0);
		}
	}
	if (typescan == SCAN_SYN)
		return (syn_scan(tabscan, packet, debug, error));
	else if (typescan == SCAN_ACK)
		return(ack_scan(tabscan, packet, debug, error));
	else if (typescan == SCAN_FIN || typescan == SCAN_NULL || typescan == SCAN_XMAS)
		return(fin_null_xmas_scan(tabscan, packet, debug, error));
	return (0);
}

int scan_udp_icmp(t_usercv *packet, bool debug)
{
	struct iphdr *ip;
	struct icmphdr *icmp;
	struct udphdr *udp;

	ip = (struct iphdr *)(packet->user + sizeof(struct ether_header) + 2);
	icmp = (struct icmphdr *)(packet->user + sizeof(struct iphdr) + sizeof(struct ether_header) + 2);
	udp = (struct udphdr *)(packet->user + sizeof(struct iphdr) + sizeof(struct ether_header) + 2 + sizeof(struct icmphdr) + sizeof(struct iphdr));

	if (debug)
	{
		if (!print_udp_icmp_pkt(ip, icmp, udp))
			return (0);
	}
	if (icmp->type == 3 && icmp->code == 3)
		return (1);
	else if (icmp->code == 3 && (icmp->type == 1 || icmp->type == 2 || icmp->type == 9 || icmp->type == 10 || icmp->type == 13))
		return (2);
	else
		return (0);
}

static int udp_scan(t_port *tabscan, t_usercv *packet, bool debug, pthread_mutex_t *mtx_debug)
{
	int ret;
	struct iphdr *ip;

	if (!packet)
	{
		if (tabscan->tries == 2)
			tabscan->port_state = PORT_OPEN_FILTER;
		return (1);
	}
	ip = (struct iphdr *)(packet->user + sizeof(struct ether_header) + 2);
	if (ip->protocol == IPPROTO_ICMP)
	{
		if ( (ret = scan_udp_icmp(packet, debug)) == 1)
			tabscan->port_state = PORT_CLOSE;
		else if (ret == 2)
			tabscan->port_state = PORT_FILTER;
	}
	else if (ip->protocol == IPPROTO_UDP)
	{
		struct udphdr *udp = (struct udphdr *)(packet->user + sizeof(struct iphdr) + sizeof(struct ether_header) + 2 + sizeof(struct icmphdr) + sizeof(struct iphdr));

		tabscan->port_state = PORT_OPEN;
		if (debug)
		{
			pthread_mutex_lock(mtx_debug);
			ret = print_udp_pkt(ip, udp);
			pthread_mutex_unlock(mtx_debug);
			return (ret);
		}
	}
	return (ret);
}

int do_the_scan(uint16_t typescan, t_port *tabscan, t_usercv *packet, bool debug, pthread_mutex_t *mtx_debug)
{
	if (typescan == SCAN_SYN || typescan == SCAN_ACK
			|| typescan == SCAN_FIN || typescan == SCAN_NULL || typescan == SCAN_XMAS)
		return (tcp_scan(typescan, tabscan, packet, debug, mtx_debug));
	else if (typescan == SCAN_UDP)
		return (udp_scan(tabscan, packet, debug, mtx_debug));
	return (0);
}
