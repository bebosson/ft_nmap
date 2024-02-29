/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bebosson <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/15 21:33:51 by bebosson          #+#    #+#             */
/*   Updated: 2018/11/20 17:45:11 by bebosson         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strmap(char const *s, char (*f)(char))
{
	unsigned	int	i;
	char			*str;

	i = -1;
	if (!s)
		return (0);
	if (!(str = (char*)malloc(ft_strlen(s) + 1)))
		return (0);
	while (s[++i])
		str[i] = f(s[i]);
	str[i] = '\0';
	return (str);
}
