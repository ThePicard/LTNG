CFLAGS = -O3 -mtune=native -fomit-frame-pointer
SRCS = $(wildcard *.c)
OBJS = $(SRCS:%.c=%.o)

.PHONY = all clean

all: ltng

ltng: $(OBJS)

clean:
	$(RM) ltng $(OBJS)
