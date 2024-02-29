/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_str_is_printable.c                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bebosson <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/21 19:57:23 by bebosson          #+#    #+#             */
/*   Updated: 2018/11/21 20:27:18 by bebosson         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int	ft_str_is_printable(char const *s)
{
	int i;

	i = 0;
	if (!s)
		return (1);
	while (s[i])
	{
		if (ft_isprint(s[i]) == 1)
			i++;
		else
			return (0);
	}
	return (1);
}
