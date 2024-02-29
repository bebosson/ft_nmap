/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bebosson <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/15 16:02:27 by bebosson          #+#    #+#             */
/*   Updated: 2018/11/15 19:24:06 by bebosson         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_itoa(int n)
{
	int		dec;
	int		nbr;
	char	*str_nbr;

	nbr = (n < 0) ? -n : n;
	dec = (n <= 0) ? 1 : 0;
	if (n < -2147483647)
		return (ft_strdup("-2147483648"));
	while (nbr > 0)
	{
		nbr /= 10;
		dec++;
	}
	if (!(str_nbr = ft_strnew(dec)))
		return (0);
	nbr = (n < 0) ? -n : n;
	while (--dec > -1)
	{
		str_nbr[dec] = nbr % 10 + '0';
		nbr /= 10;
	}
	if (n < 0)
		str_nbr[0] = '-';
	return (str_nbr);
}
