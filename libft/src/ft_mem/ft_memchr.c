/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bebosson <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/19 18:33:03 by bebosson          #+#    #+#             */
/*   Updated: 2018/11/20 16:57:21 by bebosson         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memchr(const void *s, int c, size_t n)
{
	size_t			i;
	unsigned char	d;
	unsigned char	*str;

	str = (unsigned char *)s;
	d = (unsigned char)c;
	i = 0;
	while (i < n)
	{
		if (str[i] - d == 0)
			return ((void *)str + i);
		i++;
	}
	return (0);
}
