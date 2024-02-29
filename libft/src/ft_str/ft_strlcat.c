/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bebosson <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/19 21:15:30 by bebosson          #+#    #+#             */
/*   Updated: 2018/11/19 21:16:10 by bebosson         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t	ft_strlcat(char *dst, const char *src, size_t size)
{
	size_t		dlen;
	size_t		slen;
	size_t		i;
	size_t		j;

	i = 0;
	j = 0;
	dlen = ft_strlen(dst);
	slen = ft_strlen(src);
	if (size)
	{
		while (dst[i])
			i++;
		while (src[j] && i < size - 1)
		{
			dst[i] = src[j];
			i++;
			j++;
		}
		dst[i] = '\0';
	}
	if (size >= dlen)
		return (dlen + slen);
	return (slen + size);
}
