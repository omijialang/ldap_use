OBJS=$(patsubst %.c, %.o, $(wildcard *.c))

DEBUG_LIST= #-DLHL_ENABLE_LOGGING -DLHL_ENABLE_DBG
CFLAGS= -g $(DEBUG_LIST)
LDFLAGS= -lldap

all:app

app:$(OBJS)
	gcc $^ -o $@ $(CFLAGS) $(LDFLAGS)
%.o:%.c
	gcc $< -c $(CFLAGS)

clean:
	rm -f *.o app
.PHONY: clean all
