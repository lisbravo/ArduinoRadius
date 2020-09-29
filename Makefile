# Makefile
#
# Makefile for the Arduino Radius project
#
# Author: Mike McCauley (mikem@airspayce.com)
# Copyright (C) 2009 Mike McCauley
# $Id: Makefile,v 1.1 2009/10/13 05:07:28 mikem Exp mikem $

PROJNAME = Radius
DISTFILE = $(PROJNAME)-1.2.zip

all:	doxygen dist upload

doxygen: 
	doxygen project.cfg


ci:
	ci -l `cat MANIFEST`

dist:	
	(cd ..; zip Radius/$(DISTFILE) `cat Radius/MANIFEST`)

upload:
	rsync -avz $(DISTFILE) doc/ www.airspayce.com:public_html/mikem/arduino/$(PROJNAME)
