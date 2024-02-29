#include "libft.h"

int     ft_strrnumeric(char const *s, char r)
{
        int i;

        i = 0;
        if (!s)
                return (0);
        while (s[i] && s[i] != r)
        {
                if (s[i] >= '0' && s[i] <= '9')
                        i++;
                else
                    return (0);
        }
        return (1);
}
