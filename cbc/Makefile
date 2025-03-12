CC = gcc

CFLAGS = -Wall -Wextra -O2 -Wno-sign-compare -DBLOCKSIZE=$(BLOCKSIZE)

BLOCKSIZE ?= 32

SRC = rand.c speck.c cbc.c attack.c

OBJ = $(SRC:.c=.o)

TEST_CBC = test_cbc.c

TEST_ATTACK = test_attack.c

TARGET_CBC = test_cbc

TARGET_ATTACK = test_attack
all: $(TARGET_CBC) $(TARGET_ATTACK)


$(TARGET_CBC): $(OBJ) test_cbc.o
	$(CC) $(OBJ) test_cbc.o -o $(TARGET_CBC) $(CFLAGS)

$(TARGET_ATTACK): $(OBJ) test_attack.o
	$(CC) $(OBJ) test_attack.o -o $(TARGET_ATTACK) $(CFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

run_cbc: $(TARGET_CBC)
	./$(TARGET_CBC)

run_attack: $(TARGET_ATTACK)
	./$(TARGET_ATTACK)
clean:
	rm -f $(OBJ) test_cbc.o test_attack.o $(TARGET_CBC) $(TARGET_ATTACK)