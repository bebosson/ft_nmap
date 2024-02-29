/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnew.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bebosson <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/15 16:38:42 by bebosson          #+#    #+#             */
/*   Updated: 2018/11/20 18:50:04 by bebosson         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strnew(size_t size)
{
	char	*dst;
	size_t	i;

	i = 0;
	if (!(dst = (char*)malloc(size + 1)))
		return (0);
	while (i <= size)
	{
		dst[i] = '\0';
		i++;
	}
	return (dst);
}
