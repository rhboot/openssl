# Makefile for source module: openssl
# $Id: Makefile,v 1.6 2011/11/29 19:52:47 mturk Exp $
NAME := openssl
SPECFILE = $(firstword $(wildcard *.spec))
XB_ROOT = ../../xbuild/JB-EP-6-XB

ifndef HOST_OS
HOST_OS = $(shell uname -s | sed 's/_.*//' | tr '[a-z]' '[A-Z]')
endif
ifeq (SUNOS,$(HOST_OS))
include $(XB_ROOT)/Makefile.sunspec
else
include $(XB_ROOT)/Makefile.winspec
include ../common/Makefile.common
endif
