/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bebosson <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/14 20:53:52 by bebosson          #+#    #+#             */
/*   Updated: 2018/11/15 20:04:55 by bebosson         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memmove(void *dst, const void *src, size_t len)
{
	unsigned char *st1;
	unsigned char *st2;

	st2 = (unsigned char *)src;
	st1 = (unsigned char *)dst;
	if (st1 < st2)
		while (len--)
			*st1++ = *st2++;
	else
	{
		st1 += len;
		st2 += len;
		while (len--)
			*--st1 = *--st2;
	}
	return (dst);
}
