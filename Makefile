# Makefile for source rpm: openssl
# $Id$
NAME := openssl
SPECFILE = $(firstword $(wildcard *.spec))

include ../common/Makefile.common
