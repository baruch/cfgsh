#
# This is the Makefile for the cfgsh configuration shell utility
#
# Copyright (C) 2002 Gilad Ben-Yossef <gilad@benyossef.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111 USA.

ifndef TOPDIR
TOPDIR=$(CURDIR)/
endif
ifndef top_srcdir
top_srcdir=$(CURDIR)
endif
ifndef top_builddir
top_builddir=$(CURDIR)
endif

include Rules.make

CONFIG_CONFIG_IN = config/Config.in
CONFIG_DEFCONFIG = config/defconfig

EXECUTABLES = cfgsh

.PHONY: all clean distclean menuconfig oldconfig config

all: $(EXECUTABLES)

clean:
	$(RM) $(EXECUTABLES) *.o

config/conf: config/Makefile 
	$(MAKE) -C config conf
	-@if [ ! -f .config ] ; then \
                cp $(CONFIG_DEFCONFIG) .config; \
	fi
                                                                                                                             
config/mconf: config/Makefile 
	$(MAKE) -C config ncurses conf mconf
	-@if [ ! -f .config ] ; then \
                cp $(CONFIG_DEFCONFIG) .config; \
        fi
                                                                                                                             
menuconfig: config/mconf
	@./config/mconf $(CONFIG_CONFIG_IN)
                                                                                                                             
config: config/conf
	@./config/conf $(CONFIG_CONFIG_IN)

oldconfig: config/conf
	@./config/conf -o $(CONFIG_CONFIG_IN)
                                                                                                                             
randconfig: config/conf
	@./config/conf -r $(CONFIG_CONFIG_IN)
                                                                                                                             
defconfig: config/conf
	@./config/conf -d $(CONFIG_CONFIG_IN)

distclean: clean
	$(RM) *~ core
	-$(MAKE) -C config clean
	- rm -rf include/config include/config.h
	- find . -name .depend -exec rm -f {} \;
	rm -f .config .config.old .config.cmd
	- $(MAKE) -C config clean


