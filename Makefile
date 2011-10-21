# Makefile for source module: openssl
# $Id: Makefile,v 1.2 2011/10/17 12:19:57 vtunka Exp $
NAME := openssl
SPECFILE = $(firstword $(wildcard *.spec))
WINSPEC = $(firstword $(wildcard *.ini))
XB_ROOT = ../../xbuild/JB-EP-5-XB

include $(XB_ROOT)/Makefile.winspec
include ../common/Makefile.common
