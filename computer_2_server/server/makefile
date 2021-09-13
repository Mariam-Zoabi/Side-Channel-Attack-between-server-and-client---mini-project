CC			:=	gcc
CFLAGS		:=	-ggdb -O3

SRC_DIR		:=	src
OBJ_DIR		:=	obj
BIN_DIR		:=	bin
OUT_DIR		:=	output

default: all

all: dirs | server.bin

dirs:
	mkdir -p bin obj resource messages

server.bin: $(OBJ_DIR)/server.o $(OBJ_DIR)/openssl.o $(OBJ_DIR)/init_server.o $(OBJ_DIR)/handler.o
	$(CC) $(OBJ_DIR)/server.o $(OBJ_DIR)/openssl.o $(OBJ_DIR)/init_server.o $(OBJ_DIR)/handler.o -lelf -o $(BIN_DIR)/server.bin

# *.c compile rules
$(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(BIN_DIR)/*.bin $(OBJ_DIR)/*.o $(OUT_DIR)/*.txt