/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memcpy.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bebosson <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/13 18:31:44 by bebosson          #+#    #+#             */
/*   Updated: 2018/11/13 19:15:18 by bebosson         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memcpy(void *dst, const void *src, size_t n)
{
	unsigned char *st1;
	unsigned char *st2;

	st2 = (unsigned char *)src;
	st1 = (unsigned char *)dst;
	while (n--)
		*st1++ = *st2++;
	return (dst);
}
