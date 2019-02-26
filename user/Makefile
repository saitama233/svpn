CC = gcc
CFLAGS += -Wall -Wno-uninitialized -Wno-unused-function
LIBS += -lmnl -lsutils 

CFLAGS += -g3 -DDEBUG=1 -L . -Wl,-rpath=.

RM = /bin/rm

OBJS = svpn_user.o setconf.o config.o ipc.o mnlg.o

TARGET = svpn

all: $(TARGET)

svpn: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

sources = ${OBJS:%.o=%.c}
include ${sources:.c=.d}

%.o: %.c
	$(CC) $(CFLAGS) -c $<

%.d: %.c
	set -e; \
	$(RM) -f $@; \
	$(CC) -MM $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	$(RM) -f $@.$$$$

clean:
	-$(RM) *.d *.o $(TARGET)

.PHONY: all clean
