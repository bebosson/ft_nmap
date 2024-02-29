#include "parse_addr.h"


static int  save_addr(t_env *env, struct addrinfo *ai_info)
{
	char buf[150];
	struct sockaddr_in *sock_addr;

	sock_addr = (struct sockaddr_in *)ai_info->ai_addr;
	if (inet_ntop(AF_INET, &sock_addr->sin_addr.s_addr, buf, sizeof(buf)) == NULL)
		printf("error\n");
	ft_memcpy(&env->dest_addr, &sock_addr->sin_addr, sizeof(struct in_addr));
	if(!(env->pars = ft_memalloc(sizeof(t_pars))))
		return 0;
	if(!(env->pars->buf_addr = ft_strdup(buf)))
		return 0;
	ft_memcpy(&env->pars->dest_saddr, sock_addr, sizeof(struct sockaddr_in));
	env->pars->salen = ai_info->ai_addrlen;
	return (1);
}

int reverse_addr(t_env *env, char *addr, bool parsing_ok)
{
	struct addrinfo ai_addr;
	struct addrinfo *ai_info;

	ft_memset(&ai_addr, 0, sizeof(ai_addr));
	ai_addr.ai_family = AF_INET;
	ai_addr.ai_flags = AI_CANONNAME;
	ai_addr.ai_socktype = SOCK_RAW;
	if (getaddrinfo(addr, NULL, &ai_addr, &ai_info) < 0)
		return (0);
	if (parsing_ok)
	{
		if(!(save_addr(env, ai_info)))
			return (0);
	}
	freeaddrinfo(ai_info);
	return (1);
}

int get_addr(t_env *env, char *argv)
{
	if (!reverse_addr(env, argv, 1))
		return (0);
	inet_pton(AF_INET, "127.0.0.1", &env->lo_addr);
	return (1);
}
