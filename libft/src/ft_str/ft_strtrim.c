/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bebosson <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/19 14:58:24 by bebosson          #+#    #+#             */
/*   Updated: 2018/11/24 16:10:43 by bebosson         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strtrim(char const *s)
{
	int		i;
	int		j;
	char	*str;

	if (!s)
		return (0);
	i = 0;
	j = ft_strlen(s) - 1;
	while (WH_SP(s[i]) && s[i])
		i++;
	if (!s[i])
		return (ft_strnew(0));
	while (WH_SP(s[j]) && s[j])
		j--;
	str = ft_strsub(s, i, j - i + 1);
	return (str);
}
