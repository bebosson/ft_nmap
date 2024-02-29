/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_str_is_lowercase.c                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bebosson <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/21 20:16:44 by bebosson          #+#    #+#             */
/*   Updated: 2018/11/21 20:25:42 by bebosson         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int	ft_str_is_lowercase(char const *s)
{
	int i;

	i = 0;
	if (!s)
		return (1);
	while (s[i])
	{
		if (ft_islower(s[i]) == 1)
			i++;
		else
			return (0);
	}
	return (1);
}
