/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsplit.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bebosson <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/16 15:14:44 by bebosson          #+#    #+#             */
/*   Updated: 2018/11/22 18:25:45 by bebosson         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static	int		ft_count(char const *s, char c)
{
	int i;
	int cnt_wld;

	i = 0;
	cnt_wld = 0;
	if (s[i] != c)
		cnt_wld++;
	i++;
	while (s[i])
	{
		if (s[i - 1] == c && s[i] != c)
			cnt_wld++;
		i++;
	}
	return (cnt_wld);
}

static	int		ft_count_letter(char const *s, char c, int *i)
{
	int j;

	j = 0;
	while (s[*i] != c && s[*i])
	{
		j++;
		(*i)++;
	}
	return (j);
}

char			**ft_strsplit(char const *s, char c)
{
	char	**tab_wrd;
	int		i;
	int		j;
	int		k;

	i = 0;
	k = 0;
	if (!s)
		return (NULL);
	if (!(tab_wrd = (char **)malloc(sizeof(char *) * (ft_count(s, c) + 1))))
		return (NULL);
	while (s[i])
	{
		j = ft_count_letter(s, c, &i);
		if (j != 0 && k < ft_count(s, c))
		{
			if (!(tab_wrd[k] = (char*)malloc(sizeof(char) * (j + 1))))
				return (NULL);
			tab_wrd[k] = ft_strncpy(tab_wrd[k], s + (i - j), j);
			tab_wrd[k++][j] = '\0';
		}
		i++;
	}
	tab_wrd[k] = NULL;
	return (tab_wrd);
}
