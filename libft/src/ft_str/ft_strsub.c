/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsub.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bebosson <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/16 18:36:35 by bebosson          #+#    #+#             */
/*   Updated: 2018/11/21 19:46:44 by bebosson         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strsub(char const *s, unsigned int start, size_t len)
{
	char *tr;

	if (!s)
		return (0);
	if (!(tr = (char*)malloc(sizeof(char) * (len + 1))))
		return (0);
	tr = (char *)ft_memcpy(tr, s + start, len);
	tr[len] = '\0';
	return (tr);
}
