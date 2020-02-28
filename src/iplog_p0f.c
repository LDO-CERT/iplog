/*
** iplog_p0f.c - routines used for passive fingerprinting 
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

#include <stdio.h>
#include <iplog_p0f.h>

void writepkt(char *pkt, int length) {
        int i;
        printf("examing data since: %p\n",pkt);
        for(i=0;i<length;i++) {
                printf("@ %p -> 0x%x [%d]\n",(int)pkt+i,*(pkt+i),*(pkt+i));
        }
}
int load_fprints(char *filename) {
	FILE *x;
	int i=0;
	char *p;
	
	if(filename) x=fopen(filename, "r");		  
	else x=fopen(DEFAULT_FP_FILE, "r");	  
	
	if (!x) {
		mysyslog("no '%s' file found in this dir.",DEFAULT_FP_FILE);
	} else {
		while (fgets(fps[i],FPBUF-1,x)) {
			if ((p=strchr(fps[i],'#'))) *p=0;
			if (fps[i][0]) 	i++;
		}
	}
	
	return i;
	fclose(x);
}

pktopts get_opt(const struct ip *ip,struct tcphdr *tcp) {
	char *opt_ptr;
	pktopts mypktopts;
	int opt,hlen;
	int dupa=0,olen=0;
	
	mypktopts.wscale = -1;
	mypktopts.timestamp = -1;
	mypktopts.mss = 0;
	mypktopts.nop = 0;
	mypktopts.sok = 0;
	
	
	hlen = (tcp->th_off)*4;
        opt_ptr = ((char *)tcp+sizeof(struct tcphdr));
	while(dupa<hlen) {
		opt = *(opt_ptr+dupa);
		/* getting tcp options */
		dupa++;
		switch(opt) {
			case TCPOPT_EOL:
				dupa=1000000;
				break;
			case TCPOPT_NOP:
				mypktopts.nop=1;
				break;
			case TCPOPT_SACKOK:
				mypktopts.sok=1;
				dupa++;
				break;
			case TCPOPT_MAXSEG:
				dupa++;
				mypktopts.mss=EXTRACT_16BITS(opt_ptr+dupa);
				dupa+=2;
				break;
			case TCPOPT_WSCALE:
				olen=(int)(opt_ptr+dupa)-2;
				dupa++;
				if(olen<0) olen=0;
				mypktopts.wscale=*(opt_ptr+dupa);
				dupa+=olen;
				break;
			case TCPOPT_TIMESTAMP:
				olen=(int)(opt_ptr+dupa)-2;
				dupa++;
				if(olen<0) olen=0;
				mypktopts.timestamp=*(opt_ptr+dupa);
				dupa+=olen;
				break;
			default:
				olen=(int)(opt_ptr+dupa)-2;
				dupa++;
				if(olen<0) olen=0;
				dupa+=olen;
				break;
		}
	}
	
	//writepkt(tcp,40);
	mypktopts.wss=htons(tcp->th_win);
	mypktopts.timestamp=htonl(mypktopts.timestamp);
	
	/* getting ip options */
	mypktopts.ttl = ip->ip_ttl;
	mypktopts.off=ntohs(ip->ip_off);
	mypktopts.df=((mypktopts.off&IP_DF)!=0);
	/*
	sprintf(buf,"%d:%d:%d:%d:%d:%d:%d",mypktopts.wss,mypktopts.ttl,mypktopts.mss,
		mypktopts.df,mypktopts.wscale,mypktopts.sok,mypktopts.nop);
	printf("buf: %s\n",buf);
	*/
	return mypktopts;	
}

char *get_os(const struct ip *ip,struct tcphdr *tcp) {
	char buf[FPBUF];
	char *ret;
	pktopts mypktopts;
	int i,down;
	
	mypktopts = get_opt(ip,tcp); 	
	
	for(down=0;down<TTLDW;down++) {
		sprintf(buf,"%d:%d:%d:%d:%d:%d:%d",mypktopts.wss,mypktopts.ttl+down,mypktopts.mss,
		mypktopts.df,mypktopts.wscale,mypktopts.sok,mypktopts.nop);
		
		for(i=0;i<fips;i++) {
			if(strncmp(buf,fps[i],strlen(buf)) == 0) {
				/* finger print match. getting description... */
				char *os;
				os = strrchr(fps[i],':')+1;
				if(strchr(os,'\n')) os[strlen(os)-1] = '\0';
				return os;							
			}
		}
	}
	
	/* write the original options (no ttl+down) */
	sprintf(buf,"%d:%d:%d:%d:%d:%d:%d",mypktopts.wss,mypktopts.ttl,mypktopts.mss,
		mypktopts.df,mypktopts.wscale,mypktopts.sok,mypktopts.nop);
		
	ret = malloc(FPBUF);
	sprintf(ret,"unknown (%s)",buf);
	return ret;
}
/* EOF */
