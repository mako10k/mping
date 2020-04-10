bin_PROGRAMS = mping

mping_SOURCES = mping.c mping.h
mping_LDADD = -lasyncns

AM_CFLAGS = -O3 -Wall

install-exec-hook:
	setcap cap_net_raw+eip $(DESTDIR)$(bindir)/mping

