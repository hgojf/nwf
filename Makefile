.PHONY: all clean install tidy

CFLAGS += -DPREFIX=\"$(PREFIX)\"
CFLAGS += -MD -MP
CFLAGS += -Wall -Wextra
CFLAGS += -std=c99 -pedantic

all: nwf nwf-engine

LDFLAGS_NWF = -lutil
SRCS_NWF = imsg-blocking.c nwf.c

DEPS_NWF = $(SRCS_NWF:.c=.d)
OBJS_NWF = $(SRCS_NWF:.c=.o)

nwf: $(OBJS_NWF)
	$(CC) -o $@ $(LDFLAGS_NWF) $(OBJS_NWF)

-include $(DEPS_NWF)

LDFLAGS_ENGINE = -ltls -lutil
SRCS_ENGINE = imsg-blocking.c engine.c

DEPS_ENGINE = $(SRCS_ENGINE:.c=.d)
OBJS_ENGINE = $(SRCS_ENGINE:.c=.o)

nwf-engine: $(OBJS_ENGINE)
	$(CC) -o $@ $(LDFLAGS_ENGINE) $(OBJS_ENGINE)

-include $(DEPS_ENGINE)

BINARIES = nwf nwf-engine
SRCS_ALL = engine.c imsg-blocking.c nwf.c

DEPS_ALL = $(SRCS_ALL:.c=.d)
OBJS_ALL = $(SRCS_ALL:.c=.o)

clean:
	rm -f $(BINARIES) $(DEPS_ALL) $(OBJS_ALL)

PREFIX ?= /usr/local
MANPATH ?= $(PREFIX)/man

install:
	$(INSTALL) -m 0755 nwf $(PREFIX)/bin
	$(INSTALL) -m 0755 nwf-engine $(PREFIX)/libexec

tidy:
	clang-tidy $(SRCS_ALL) -- $(CFLAGS)
