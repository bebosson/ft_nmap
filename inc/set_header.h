#ifndef SET_HEADER_H
#define SET_HEADER_H


void		set_tcp_syn_header(void **tcp, int src_port, int dst_port);
void		set_tcp_fin_header(void **tcp, int src_port, int dst_port);
void		set_tcp_ack_header(void **tcp, int src_port, int dst_port);
void		set_tcp_null_header(void **tcp, int src_port, int dst_port);
void		set_tcp_xmas_header(void **tcp, int src_port, int dst_port);
void		set_udp_header(void **tcp, int src_port, int dst_port);

#endif
