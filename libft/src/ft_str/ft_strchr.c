/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bebosson <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/10 16:02:45 by bebosson          #+#    #+#             */
/*   Updated: 2018/11/19 18:40:11 by bebosson         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strchr(const char *s, int c)
{
	int				i;
	unsigned char	d;

	d = (unsigned char)c;
	i = 0;
	while (s[i])
	{
		if (s[i] - d == 0)
			return ((char *)s + i);
		i++;
	}
	if (s[i] - d == 0)
		return ((char*)s + i);
	return (0);
}
