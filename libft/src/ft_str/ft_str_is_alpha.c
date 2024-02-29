/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_str_is_alpha.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bebosson <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/21 19:09:22 by bebosson          #+#    #+#             */
/*   Updated: 2018/11/21 19:42:41 by bebosson         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		ft_str_is_alpha(char const *s)
{
	int i;

	i = 0;
	if (!s)
		return (1);
	while (s[i])
	{
		if (ft_isalpha(s[i]) == 1)
			i++;
		else
			return (0);
	}
	return (1);
}
