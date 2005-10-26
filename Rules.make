#--------------------------------------------------------
PROG      := cfgsh
VERSION   := 1.1.3
BUILDTIME := $(shell TZ=UTC date -u "+%Y.%m.%d-%H:%M%z")

# If you are running a cross compiler, you will want to set 'CROSS'
# to something more interesting...  Target architecture is determined
# by asking the CC compiler what arch it compiles things for, so unless
# your compiler is broken, you should not need to specify TARGET_ARCH

CROSS           =$(subst ",, $(strip $(CROSS_COMPILER_PREFIX)))
CC             = $(CROSS)gcc
AR             = $(CROSS)ar
AS             = $(CROSS)as
LD             = $(CROSS)ld
NM             = $(CROSS)nm
STRIP          = $(CROSS)strip
CPP            = $(CC) -E

# Select the compiler needed to build binaries for your development system
HOSTCC    = gcc
HOSTCFLAGS= -Wall -Wstrict-prototypes -O2 -fomit-frame-pointer

WARNINGS=-Wall -Wstrict-prototypes -Wshadow
CFLAGS=-I$(top_builddir)/include 
LDFLAGS =  -lcurses -lreadline -lpthread -lrt
ARFLAGS=-r


export VERSION BUILDTIME TOPDIR HOSTCC HOSTCFLAGS CROSS CC AR AS LD NM STRIP CPP

ifeq ($(strip $(ARCH)),)
ARCH=$(shell $(CC) -dumpmachine | sed -e s'/-.*//' \
                -e 's/i.86/i386/' \
                -e 's/sparc.*/sparc/' \
                -e 's/arm.*/arm/g' \
                -e 's/m68k.*/m68k/' \
                -e 's/ppc/powerpc/g' \
                -e 's/v850.*/v850/g' \
                -e 's/sh[234]/sh/' \
                -e 's/mips-.*/mips/' \
                -e 's/mipsel-.*/mipsel/' \
                -e 's/cris.*/cris/' \
                )
endif

# A nifty macro to make testing gcc features easier
check_gcc=$(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null > /dev/null 2>&1; \
        then echo "$(1)"; else echo "$(2)"; fi)
                                                                                                                             
#--------------------------------------------------------
# Arch specific compiler optimization stuff should go here.
# Unless you want to override the defaults, do not set anything
# for OPTIMIZATION...
                                                                                                                             
# use '-Os' optimization if available, else use -O2
OPTIMIZATION=
OPTIMIZATION=${call check_gcc,-Os,-O2}
                                                                                                                             
# Some nice architecture specific optimizations
ifeq ($(strip $(ARCH)),arm)
        OPTIMIZATION+=-fstrict-aliasing
endif

ifeq ($(strip $(ARCH)),i386)
        OPTIMIZATION+=$(call check_gcc,-march=i386,)
        OPTIMIZATION+=$(call check_gcc,-mpreferred-stack-boundary=2,)
        OPTIMIZATION+=$(call check_gcc,-falign-functions=0 -falign-jumps=0 -falign-loops=0,\
                -malign-functions=0 -malign-jumps=0 -malign-loops=0)
endif
OPTIMIZATIONS=$(OPTIMIZATION) -fomit-frame-pointer

# Pull in the user's busybox configuration
-include $(top_builddir)/.config

