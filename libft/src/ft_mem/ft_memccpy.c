/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memccpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bebosson <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/14 15:32:00 by bebosson          #+#    #+#             */
/*   Updated: 2018/11/20 17:25:06 by bebosson         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memccpy(void *dst, const void *src, int c, size_t n)
{
	unsigned char *st1;
	unsigned char *st2;

	st2 = (unsigned char *)src;
	st1 = (unsigned char *)dst;
	while (n--)
	{
		*st1 = *st2;
		if (*st2 == (unsigned char)c)
		{
			return ((void *)st1 + 1);
		}
		st1++;
		st2++;
	}
	return (NULL);
}
