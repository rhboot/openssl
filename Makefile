# Makefile for source module: openssl
# $Id: Makefile,v 1.1 2004/09/09 09:35:04 cvsdist Exp $
NAME := openssl
SPECFILE = $(firstword $(wildcard *.spec))

BUILD_CLIENT = brew win-build
WINSPEC = $(firstword $(wildcard *.ini))
NAME = $(shell awk -F ' *= *' '{if ($$1 == "name") {print $$2; exit}}' $(WINSPEC))
VERSION = $(shell awk -F ' *= *' '{if ($$1 == "version") {print $$2; exit}}' $(WINSPEC))
RELEASE = $(shell awk -F ' *= *' '{if ($$1 == "release") {print $$2; exit}}' $(WINSPEC))
DIST = $(shell awk -F ' *= *' '{if ($$1 == "dist") {print $$2; exit}}' $(WINSPEC))
# Use VM version directly from .ini file
# replace with VM = jboss-natives-20110516-1 if it fails
#
VM = $(shell awk -F ' *= *' '{if ($$1 == "vm") {print $$2; exit}}' $(WINSPEC))

include ../common/Makefile.common

win-build: check-build
	@echo "Attempting build of package $(NAME)-$(VERSION)-$(RELEASE) on $(VM)"
	@$(BUILD_CLIENT) $(BUILD_FLAGS) $(COLLECTION) \
	'cvs://cvs.devel.redhat.com/cvs/dist?$(CVS_REPOSITORY)#$(TAG)' $(VM)
