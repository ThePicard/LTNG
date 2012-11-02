#CFLAGS = -O3 -mtune=native -fomit-frame-pointer
CFLAGS = -g
SRCS = $(wildcard *.c)
OBJS = $(SRCS:%.c=%.o)
LIBS = http-parser/libhttp_parser.a

.PHONY = all clean

all: ltng

ltng: $(OBJS) $(LIBS)

http-parser/libhttp_parser.a:
	make -C http-parser package

clean:
	$(RM) ltng $(OBJS)
