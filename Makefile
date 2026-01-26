SRC := $(wildcard src/*.c)

NAME = euclid

RM = rm -f

CP = cp -f -r

DESTDIR = /usr/bin/

SRCMAN = man/

MANPAGE = euclid.1

COMPMAN = euclid.1.gz 

COMPRESS = gzip < $(SRCMAN)$(MANPAGE) > $(SRCMAN)$(COMPMAN)

MANDIR = /usr/share/man/man1/

MANDB = mandb

CC = gcc

BIN_DIR = bin

BUILD_DIR = build

OBJS = $(SRC:src/%.c=$(BUILD_DIR)/%.o)

CFLAGS = -Wall -Wextra -pedantic -g -I include

all: bin $(BIN_DIR)/$(NAME)

$(BIN_DIR)/$(NAME): $(OBJS)
	$(CC) -o $(BIN_DIR)/$(NAME) $(OBJS)

$(BUILD_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) -g $(CFLAGS) -c $< -o $@

bin:
	mkdir -p $(BIN_DIR)

clean:
	rm -f $(OBJS)
	rm -rf $(BUILD_DIR)

cleanMan:
	rm -f $(SRCMAN)$(COMPMAN)

fclean: clean cleanMan
	rm -rf $(BIN_DIR)

install: $(BIN_DIR)/$(NAME) 
	cp -f -r $(BIN_DIR)/$(NAME) $(DESTDIR)
	$(COMPRESS)
	cp -f -r $(SRCMAN)$(COMPMAN) $(MANDIR)
	$(MANDB)

re: fclean all

uninstall: $(NAME)
	rm -f $(DESTDIR)$(NAME)
	rm -f $(MANDIR)$(COMPMAN)
	$(MANDB)

.PHONY: all bin clean cleanMan fclean install re uninstall
