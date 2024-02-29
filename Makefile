.POSIX:
CC = gcc -fsanitize=leak -g3
#CC = gcc -g
CFLAGS = -Wall -Wextra -Werror
PROG = ft_nmap
OBJ = obj
OBJS = ${OBJ}/ft_nmap.o ${OBJ}/parse_addr.o ${OBJ}/parse_ports.o \
		${OBJ}/parse_scan.o ${OBJ}/send.o ${OBJ}/set_env.o ${OBJ}/set_pcap.o \
		${OBJ}/set_header.o ${OBJ}/pack_reader.o ${OBJ}/ptr_scan.o \
		 ${OBJ}/thread.o ${OBJ}/display_result.o ${OBJ}/parse_args.o \
		 ${OBJ}/exec.o
SRC = src
INC = inc
INCS = ${INC}/ft_nmap.h  ${INC}/parse_addr.h ${INC}/parse_ports.h \
			${INC}/parse_scan.h ${INC}/send.h ${INC}/set_env.h \
			${INC}/set_header.h ${INC}/set_pcap.h ${INC}/pack_reader.h ${INC}/ptr_scan.h \
			${INC}/thread.h ${INC}/display_result.h ${INC}/parse_args.h \
			${INC}/exec.h
LIBFT = libft
LIBFT_LINK = libft/libft.a
MAKEFILE = Makefile

all: ${PROG}

${OBJ}/ft_nmap.o: ${SRC}/ft_nmap.c ${INC}/ft_nmap.h \
			${INC}/parse_args.h ${INC}/exec.h ${INC}/send.h ${INC}/display_result.h
	mkdir -p ${OBJ}
	${CC} -Iinc -Ilibft/includes ${CFLAGS} -o $@ -c $<
	@echo "=> Compiled "$<" successfully!"

${OBJ}/parse_addr.o: ${SRC}/parse_addr.c ${INC}/parse_addr.h
	${CC} -Iinc -Ilibft/includes ${CFLAGS} -o $@ -c $<
	@echo "=> Compiled "$<" successfully!"

${OBJ}/parse_ports.o: ${SRC}/parse_ports.c ${INC}/parse_ports.h \
			${INC}/set_env.h
	${CC} -Iinc -Ilibft/includes ${CFLAGS} -o $@ -c $<
	@echo "=> Compiled "$<" successfully!"

${OBJ}/parse_scan.o: ${SRC}/parse_scan.c ${INC}/parse_scan.h
	${CC} -Iinc -Ilibft/includes ${CFLAGS} -o $@ -c $<
	@echo "=> Compiled "$<" successfully!"

${OBJ}/send.o: ${SRC}/send.c ${INC}/send.h \
			${INC}/set_env.h ${INC}/ptr_scan.h ${INC}/pack_reader.h \
			${INC}/display_result.h ${INC}/ft_nmap.h
	${CC} -Iinc -Ilibft/includes ${CFLAGS} -o $@ -c $<
	@echo "=> Compiled "$<" successfully!"

${OBJ}/set_env.o: ${SRC}/set_env.c ${INC}/set_env.h \
			${INC}/set_header.h
	${CC} -Iinc -Ilibft/includes ${CFLAGS} -o $@ -c $<
	@echo "=> Compiled "$<" successfully!"

${OBJ}/set_pcap.o: ${SRC}/set_pcap.c ${INC}/set_pcap.h
	${CC} -Iinc -Ilibft/includes ${CFLAGS} -o $@ -c $<
	@echo "=> Compiled "$<" successfully!"

${OBJ}/set_header.o: ${SRC}/set_header.c
	${CC} -Iinc -Ilibft/includes ${CFLAGS} -o $@ -c $<
	@echo "=> Compiled "$<" successfully!"

${OBJ}/pack_reader.o: ${SRC}/pack_reader.c ${INC}/pack_reader.h \
			${INC}/display_result.h ${INC}/ptr_scan.h 
	${CC} -Iinc -Ilibft/includes ${CFLAGS} -o $@ -c $<
	@echo "=> Compiled "$<" successfully!"

${OBJ}/ptr_scan.o: ${SRC}/ptr_scan.c ${INC}/ptr_scan.h ${INC}/ft_nmap.h \
			${INC}/display_result.h
	${CC} -Iinc -Ilibft/includes ${CFLAGS} -o $@ -c $<
	@echo "=> Compiled "$<" successfully!"

${OBJ}/display_result.o: ${SRC}/display_result.c ${INC}/display_result.h \
			${INC}/ft_nmap.h
	${CC} -Iinc -Ilibft/includes ${CFLAGS} -o $@ -c $<
	@echo "=> Compiled "$<" successfully!"

${OBJ}/parse_args.o: ${SRC}/parse_args.c ${INC}/parse_args.h \
			${INC}/parse_addr.h ${INC}/parse_scan.h ${INC}/parse_ports.h \
			${INC}/set_env.h ${INC}/set_pcap.h
	${CC} -Iinc -Ilibft/includes ${CFLAGS} -o $@ -c $<
	@echo "=> Compiled "$<" successfully!"

${OBJ}/exec.o: ${SRC}/exec.c ${INC}/exec.h\
			${INC}/thread.h
	${CC} -Iinc -Ilibft/includes ${CFLAGS} -o $@ -c $<
	@echo "=> Compiled "$<" successfully!"

${OBJ}/thread.o:  ${SRC}/thread.c ${INC}/thread.h \
			${INC}/set_pcap.h ${INC}/send.h ${INC}/pack_reader.h
	${CC} -Iinc -Ilibft/includes ${CFLAGS} -o $@ -c $<
	@echo "=> Compiled "$<" successfully!"

${PROG}: ${LIBFT_LINK} ${INCS} ${MAKEFILE} ${OBJS}
	${CC} -o $@ ${OBJS} -Llibft -lft -lpcap -pthread
	@echo "=> Linking complete!"

${LIBFT_LINK}:
	git submodule init
	git submodule update
	make -C ${LIBFT}

clean:
	-rm -rf ${OBJ} *.txt
	@echo "=> Object files deleted."
	make -C ${LIBFT} clean

fclean:
	-rm -rf ${OBJ} ${PROG} ${PROG:=.core} *.txt
	@echo "=> All executables deleted."
	make -C ${LIBFT} fclean

re: fclean all

.PHONY: all clean fclean re 
