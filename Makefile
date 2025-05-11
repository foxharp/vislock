version = 14

srcdir = .
VPATH = $(srcdir)

PREFIX = /usr/local
MANPREFIX = $(PREFIX)/share/man

# enable user detection using libsystemd or libelogind.  if
# neither is enabled, the utmp file will be consulted.
HAVE_SYSTEMD = 1
HAVE_ELOGIND = 0

cflags = -Wall -Wno-format -pedantic $(CFLAGS) -g
cppflags = -I. $(CPPFLAGS) \
  -DHAVE_SYSTEMD=$(HAVE_SYSTEMD) -DHAVE_ELOGIND=$(HAVE_ELOGIND)

lib_systemd_0 =
lib_systemd_1 = -lsystemd
lib_elogind_0 =
lib_elogind_1 = -lelogind
ldlibs = $(LDLIBS) -lpam -lpam_misc \
  $(lib_systemd_$(HAVE_SYSTEMD)) $(lib_elogind_$(HAVE_ELOGIND))

objs = main.o options.o session.o util.o vt.o

all: vislock

.PHONY: all clean install uninstall
.SUFFIXES:
.SUFFIXES: .c .o
$(V).SILENT:

vislock: $(objs)
	@echo "LINK $@"
	$(CC) $(LDFLAGS) -o $@ $(objs) $(ldlibs)

$(objs): Makefile vislock.h config.h
options.o: version.h

.c.o:
	@echo "CC $@"
	$(CC) $(cflags) $(cppflags) -c -o $@ $<

config.h: config.def.h
	@echo "GEN $@"
	cp $(srcdir)/config.def.h $@

version.h: Makefile .git/index
	@echo "GEN $@"
	v="$$(cd $(srcdir); git describe 2>/dev/null)"; \
	echo "#define VERSION \"$${v:-$(version)}\"" >$@

.git/index:

clean:
	rm -f *.o vislock

install: all
	@echo "INSTALL bin/vislock"
	install -D -m 4755 -o root -g root vislock \
		$(DESTDIR)$(PREFIX)/bin/vislock
	@echo "INSTALL vislock.1"
	mkdir -p $(DESTDIR)$(MANPREFIX)/man1
	v="$$(sed -n -e 's/.*VERSION "\(.*\)"/\1/p' version.h)"; \
	sed "s/VERSIONSTRING/$${v}/g" vislock.1 > \
		$(DESTDIR)$(MANPREFIX)/man1/vislock.1
	chmod 644 $(DESTDIR)$(MANPREFIX)/man1/vislock.1

uninstall:
	@echo "REMOVE bin/vislock"
	rm -f $(DESTDIR)$(PREFIX)/bin/vislock
	@echo "REMOVE vislock.1"
	rm -f $(DESTDIR)$(MANPREFIX)/man1/vislock.1

