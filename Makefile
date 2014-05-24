CXX = c++
CXXFLAGS ?= -Wall -Wextra -pedantic -O2
PREFIX = /usr/local

PROGRAMS = logmailer
#MANPAGES = logmailer.8
OBJFILES = logmailer.o

all: $(PROGRAMS)

logmailer: $(OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o $(PROGRAMS)

install:
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(PROGRAMS) $(DESTDIR)$(PREFIX)/bin/
#	install -d $(DESTDIR)$(PREFIX)/share/man
#	install -m 644 $(MANPAGES) $(DESTDIR)$(PREFIX)/share/man/

.PHONY: all clean install
