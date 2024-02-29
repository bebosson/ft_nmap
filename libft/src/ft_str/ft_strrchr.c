/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strrchr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bebosson <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/20 14:09:49 by bebosson          #+#    #+#             */
/*   Updated: 2018/11/20 15:25:39 by bebosson         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strrchr(const char *s, int c)
{
	int					i;
	unsigned char		d;

	d = (unsigned char)c;
	i = ft_strlen(s);
	(c == '\0') ? i : i--;
	while (i > 0)
	{
		if (s[i] - d == 0)
			return ((char *)s + i);
		i--;
	}
	if (s[i] - d == 0)
		return ((char *)s + i);
	return (0);
}
