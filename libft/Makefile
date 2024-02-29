# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: bebosson <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2021/08/12 17:38:05 by bebosson          #+#    #+#              #
#    Updated: 2021/08/12 22:19:08 by bebosson         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

#	project

NAME	=	libft.a
SRC_PATH = src

CC		=	gcc
CFLAGS	=	-Wall -Wextra -Werror

#	src lst

SRCS_CHAR =	ft_isalnum.c		ft_isascii.c	ft_islower.c	ft_isupper.c	\
			ft_toupper.c		ft_isalpha.c	ft_isdigit.c	ft_isprint.c	\
			ft_tolower.c
SRCS_LST	=	ft_lstadd.c			ft_lstdel.c		ft_lstdelone.c	ft_lstiter.c	\
			ft_lstmap.c			ft_lstnew.c

SRCS_MEM =	ft_bzero.c		ft_memccpy.c	ft_memcmp.c		ft_memdel.c		\
			ft_memset.c		ft_memalloc.c	ft_memchr.c		ft_memcpy.c   \
			ft_memmove.c
SRCS_NB =	ft_atoi.c		ft_itoa.c	\

SRCS_PUT	=	ft_putchar.c	ft_putendl.c	ft_putnbr.c		ft_putstr.c		\
			ft_putchar_fd.c		ft_putendl_fd.c		ft_putnbr_fd.c		\
			ft_putstr_fd.c
SRCS_STR =	ft_str_is_alpha.c	ft_strcpy.c		ft_strlen.c		ft_strnstr.c	\
			ft_str_is_lowercase.c	ft_strdel.c		ft_strmap.c		ft_strrchr.c	\
			ft_str_is_numeric.c		ft_strdup.c	ft_strmapi.c	ft_strsplit.c	\
			ft_str_is_printable.c	ft_strequ.c	ft_strncat.c	ft_strstr.c	\
			ft_strcat.c		ft_striter.c 		ft_strncmp.c	ft_strsub.c	\
			ft_strchr.c		ft_striteri.c		ft_strncpy.c	ft_strtrim.c	\
			ft_strclr.c		ft_strjoin.c 		ft_strnequ.c	ft_strrnumeric.c \
			ft_strcmp.c		ft_strlcat.c		ft_strnew.c	

GNL = get_next_line.c

SRC_NAME =	$(addprefix ft_char/,   $(SRCS_CHAR))	\
			$(addprefix ft_lst/,     $(SRCS_LST))	\
			$(addprefix ft_mem/,    $(SRCS_MEM))	\
			$(addprefix ft_nb/,     $(SRCS_NB))		\
			$(addprefix ft_str/,    $(SRCS_STR))	\
			$(addprefix ft_put/,   $(SRCS_PUT))		\
			$(addprefix gnl/,   $(GNL))

SRC = $(addprefix $(SRC_PATH)/,$(SRC_NAME))

OBJ 	=	$(SRC:.c=.o)

INCDIR	=	./includes
INC		= 	libft.h
HEADER  =       $(addprefix $(INCDIR)/,$(INC))

###			Colors		###

BLACK   =       \033[30m
RED     =       \033[31m
GREEN   =       \033[32m
YELLOW  =       \033[33m
BLUE    =       \033[34m
PURPLE  =       \033[35m
TUR     =       \033[36m
WHITE   =       \033[37m
END     =       \033[0m

UP      = 	\033[A
CUT     =   \033[K
UP 		=	\033[A
CUT 	=	\033[K

all:		$(NAME)

%.o:		%.c
			@echo "${TUR}compiling [$@] ...${END}"
			@$(CC) $(CFLAGS) -I $(INCDIR) -c -o $@ $<
			@printf "$(UP)$(CUT)"

$(NAME):	$(OBJ) $(HEADER)
			@ar rcs $(NAME) $(OBJ)

clean:
			@/bin/rm -rf $(OBJ)

fclean:		clean
			@/bin/rm -rf $(NAME)

re:			fclean all

.PHONY:		all clean fclean re
