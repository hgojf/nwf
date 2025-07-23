.PHONY: all clean

CFLAGS += -Wall -Wextra

all: nwf nwf-engine

LDFLAGS_NWF = -lutil
SRCS_NWF = imsg-blocking.c nwf.c

DEPS_NWF = $(SRCS_NWF:.c=.d)
OBJS_NWF = $(SRCS_NWF:.c=.o)

nwf: $(OBJS_NWF)
	$(CC) -o $@ $(LDFLAGS_NWF) $(OBJS_NWF)

LDFLAGS_ENGINE = -ltls -lutil
SRCS_ENGINE = imsg-blocking.c engine.c

DEPS_ENGINE = $(SRCS_ENGINE:.c=.d)
OBJS_ENGINE = $(SRCS_ENGINE:.c=.o)

nwf-engine: $(OBJS_ENGINE)
	$(CC) -o $@ $(LDFLAGS_ENGINE) $(OBJS_ENGINE)

BINARIES = nwf nwf-engine
SRCS_ALL = engine.c imsg-blocking.c nwf.c

DEPS_ALL = $(SRCS_ALL:.c=.d)
OBJS_ALL = $(SRCS_ALL:.c=.o)

clean:
	rm -f $(BINARIES) $(DEPS_ALL) $(OBJS_ALL)
