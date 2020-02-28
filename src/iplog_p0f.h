/*
** iplog_p0f.h - header file used by iplog_p0f.c 
** Copyright (C) 1999-2001 emmekappa <emmekappa@openbeer.it>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License, version 2,
** as published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
**
*/

#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iplog.h>

#define DEFAULT_FP_FILE "/etc/iplog/p0f.fp"
#define FPBUF 120
#define MAXFPS 1000
#define TTLDW  30
#define EXTRACT_16BITS(p) \
        ((u_short)*((u_char *)(p) + 0) << 8 | (u_short)*((u_char *)(p) + 1))

/* this struct contains packet options */ 
struct s_pktopts {
	int wss;
	int wscale;
	int mss;
	int nop;
	int ttl;
	int df;
	int sok;
	int off;
	u_int32_t timestamp;
};

typedef struct s_pktopts pktopts;

/* global var */
char fps[MAXFPS][FPBUF];
int  fips;

/* routines */
int load_fprints(char *filename);
pktopts get_opt(const struct ip *ip,struct tcphdr *tcp);
char *get_os(const struct ip *ip,struct tcphdr *tcp);
