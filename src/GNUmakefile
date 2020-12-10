CC 		= gcc

CFLAGS 		= -Wall
LFLAGS		= -pthread -lpq -lm -lulfius -ljansson

INC_DIR		= ../inc
OBJ_DIR		= ../obj
BIN_DIR		= ../bin
SRC_DIR		= .

INCLUDES 	= -I/usr/include/postgresql \
		  -I$(INC_DIR)

TARGET 		= $(BIN_DIR)/gateway

#
SRCS		= $(wildcard $(SRC_DIR)/*.c)
OBJS		= $(patsubst $(SRC_DIR)%.c, $(OBJ_DIR)%.o, $(SRCS))
#


$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJS) -o $(TARGET) $(LFLAGS)

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -c -MD $(CFLAGS) $(INCLUDES) $< -o $@

-include $(OBJ_DIR)/*.d

.PHONY: clean print

clean :
	rm -f $(BIN_DIR)/* $(OBJ_DIR)/*

print :
	$(info $$OBJS is [${OBJS}])
