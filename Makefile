CC     ?= clang
CFLAGS ?= -Wall -Wextra -O3
LDLIBS ?=

TARGET = mpqextract
SRC    = main.c miniz.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LDLIBS)

clean:
	rm -f $(TARGET)
