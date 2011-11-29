# Makefile for source module: openssl
# $Id: Makefile,v 1.3 2011/10/21 15:15:35 vtunka Exp $
NAME := openssl
SPECFILE = $(firstword $(wildcard *.spec))
XB_ROOT = ../../xbuild/JB-EP-6-XB

ifndef OS
$(error "You can not run this Makefile without having OS defined")
endif
ifeq (windows,$(OSTYPE))
WINSPEC = $(firstword $(wildcard *.ini))
include $(XB_ROOT)/Makefile.winspec
include ../common/Makefile.common
else ifeq (solaris,$(OSTYPE))
SUNSPEC = $(firstword $(wildcard *.ini))
include $(XB_ROOT)/Makefile.sunspec
else
$(error "Don't know how to build for $(OSTYPE) os.")
endif
