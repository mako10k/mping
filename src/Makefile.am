bin_PROGRAMS = mping

mping_SOURCES = mping.c

AM_CFLAGS = -O3 -Wall

install-exec-hook:
	setcap cap_net_raw+eip $(DESTDIR)$(bindir)/mping

