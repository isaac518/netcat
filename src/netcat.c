/*
 * netcat.c -- main project file
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002 - 2003  Giovanni Giacobbi
 *
 * $Id: netcat.c,v 1.63 2003/08/21 15:27:18 themnemonic Exp $
 */

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE
#include "netcat.h"
#include <signal.h>
#include <getopt.h>
#include <time.h>		/* time(2) used as random seed */
#include <sys/wait.h>
#include <poll.h>

/* int gatesidx = 0; */		/* LSRR hop count */
/* int gatesptr = 4; */		/* initial LSRR pointer, settable */
/* nc_host_t **gates = NULL; */	/* LSRR hop hostpoop */
/* char *optbuf = NULL; */	/* LSRR or sockopts */
FILE *output_fp = NULL;		/* output fd (FIXME: i don't like this) */
bool use_stdin = TRUE;		/* tells wether stdin was closed or not */
bool signal_handler = TRUE;	/* handle the signals externally */
bool got_sigterm = FALSE;	/* when this TRUE the application must exit */
bool got_sigint = FALSE;	/* when this TRUE the application should exit */
bool got_sigusr1 = FALSE;	/* when set, the application should print stats */
bool commandline_need_newline = FALSE;	/* fancy output handling */

/* global options flags */
nc_mode_t netcat_mode = 0;	/* Netcat working modality */
bool opt_multi_pr = FALSE;  /// last-listening for tunnel mode */
bool opt_eofclose = FALSE;	/* close connection on EOF from stdin */
bool opt_debug = FALSE;		/* debugging output */
bool opt_numeric = FALSE;	/* don't resolve hostnames */
bool opt_random = FALSE;	/* use random ports */
bool opt_udpmode = FALSE;	/* use udp protocol instead of tcp */
bool opt_telnet = FALSE;	/* answer in telnet mode */
bool opt_hexdump = FALSE;	/* hexdump traffic */
bool opt_zero = FALSE;		/* zero I/O mode (don't expect anything) */
bool opt_heartbeat = FALSE; /* heartbeat mode for SWITCH and BRIDGE */
#define HEARTBEAT_INTERVAL 5000
#define HEARTBEAT_MSG "NETCAT!!"
#define HEARTBEAT_MSG_LEN 8
double opt_interval = 0.0;		/* delay (in seconds) between lines/ports */
int opt_verbose = 0;		/* be verbose (> 1 to be MORE verbose) */
int opt_wait = 0;		    /* wait time */
char *opt_outputfile = NULL;	/* hexdump output file */
char *opt_exec = NULL;		/* program to exec after connecting */
nc_proto_t opt_proto = NETCAT_PROTO_TCP; /* protocol to use for connections */

///For Verification mode. added at 20231123
int opt_chosen=0;
char * opt_signature_in = NULL;
char * opt_signature_out = NULL;
char * banner1 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3\n";
char * banner2 = "Invalid SSH identification string.\n";
static int verify_signature(int fd)
{   
    char rbuf[16];
    char textbuf[128];
    int ready,siglen,read_ret;
    time_t t,i;
    unsigned char res[16];
    fd_set rdfds;
    struct timeval timeout;

    memset(&timeout,0,sizeof(struct timeval)); //tv.tv_sec,tv.tv_usec
    timeout.tv_usec=500000; //wait 0.5 second
    FD_ZERO(&rdfds);
    FD_SET(fd,&rdfds);
    ready=select(fd+1,&rdfds,NULL,NULL,&timeout);

    if(ready>0 && FD_ISSET(fd,&rdfds)) {
        read_ret = read(fd, rbuf, 16); //sizeof md5sum
        if(read_ret!=16) {  ///not passed or remote fd closed
            write(fd,banner1,strlen(banner1));
            write(fd,banner2,strlen(banner2));
            close(fd);
            return FALSE;
        }
    debug_dv(("read(net) = %d", read_ret));

        /* start md5 comparing */
        siglen=strlen(opt_signature_in);
        strncpy(textbuf,opt_signature_in,siglen);
        t=time(NULL);
        
        sprintf(textbuf+siglen,"%ld",t);
        memset(res,0,sizeof(res));
        __md5_buffer(textbuf,strlen(textbuf),res);
        if(!memcmp(rbuf,res,16)) {
    debug_dv(("memcmp OK"));
            return TRUE;
        }

        for(i=1;i<4;i++) {  //if time unsynchoronized
            sprintf(textbuf+siglen,"%ld",t-i);
            memset(res,0,sizeof(res));
            __md5_buffer(textbuf,strlen(textbuf),res);
            if(!memcmp(rbuf,res,16)) {
    debug_dv(("memcmp OK")); 
                return TRUE;
            }
            sprintf(textbuf+siglen,"%ld",t+i);
            memset(res,0,sizeof(res));
            __md5_buffer(textbuf,strlen(textbuf),res);
            if(!memcmp(rbuf,res,16)) {
    debug_dv(("memcmp OK")); 
                return TRUE;
            }
        }

    debug_dv(("memcmp Wrong")); 
        write(fd,banner1,strlen(banner1));
        write(fd,banner2,strlen(banner2));
    }
    if(!ready) {
    debug_dv(("select() for signature timed out")); 
        write(fd,banner1,strlen(banner1));
    }
    close(fd);
    return FALSE;
}
void send_signature(int fd) {
/* already test write available in core_tcp_connect() */ 
    static char buf[64];
    static unsigned char res[16];
    static int siglen;
    static time_t t;
    siglen=strlen(opt_signature_out);
    strncpy(buf,opt_signature_out,siglen);
    t=time(NULL);
    sprintf(buf+siglen,"%ld",t);
debug_v(("Original String is %s", buf));
    memset(res,0,sizeof(res));
    __md5_buffer(buf,strlen(buf),res);
    write(fd,res,16);
}

char *search_arg(char **argv, char *arg) {
    char **argp;
    for(argp=argv;*argp!=0;argp++)
    {
        if(strstr(*argp,arg))
            return *argp;
    }
    return NULL;
}

/* signal handling */
static void got_child(int z)
{
    int savedErrno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        continue;
    errno = savedErrno;
}

static void got_term(int z) ///exit immediately
{
  if (!got_sigterm)
    ncprint(NCPRINT_VERB1, _("Terminated."));
  debug_v(("_____ RECEIVED SIGTERM _____ [signal_handler=%s]",
	  BOOL_TO_STR(signal_handler)));
  got_sigterm = TRUE;
  if (signal_handler)			/* default action at external handler*/
    exit(EXIT_FAILURE);
}

static void got_int(int z) ///if in core_readwrite(), close current connection and continue next port
{
  if (!got_sigint)
    ncprint(NCPRINT_VERB1, _("Exiting."));
  debug_v(("_____ RECEIVED SIGINT _____ [signal_handler=%s]",
	  BOOL_TO_STR(signal_handler)));
  got_sigint = TRUE;
  if (signal_handler) {			/* default action */
    if (commandline_need_newline)	/* if we were waiting for input */
      printf("\n");
    netcat_printstats(FALSE);
    exit(EXIT_FAILURE);
  }
}

static void got_usr1(int z)
{
  debug_dv(("_____ RECEIVED SIGUSR1 _____ [signal_handler=%s]",
	   BOOL_TO_STR(signal_handler)));
  if (signal_handler)			/* default action */
    netcat_printstats(TRUE);
  else
    got_sigusr1 = TRUE;
}

/* Execute an external file making its stdin/stdout/stderr the actual socket */

static void ncexec(nc_sock_t *ncsock)
{
  int saved_stderr;
  char *p,*q;
  char *command=strdup(opt_exec); ///save the original command string.
  assert(ncsock && (ncsock->fd >= 0));

  /* change the label for the executed program */
  if ((q=strchr(opt_exec, ' '))||(q=strchr(opt_exec, '\t'))) ///if args has a '/'
      *q='\0';
  if ((p = strrchr(opt_exec, '/')))
    p++;			/* shorter argv[0] */
  else
    p = opt_exec;
  if(q)
      *q=' ';

  /* support arguments of the exec program. */
#define MAX_EXEC_ARGC 20
  char *exec_name;
  char *exec_argv[MAX_EXEC_ARGC]; ///allocated conveniently, maybe not enough :)
  int   exec_argc=0;
  memset(exec_argv,0,sizeof(exec_argv));
  debug_dv(("sizeof(exec_argv)=%d", sizeof(exec_argv)));

  exec_name=p;
  exec_argv[0]=exec_name;
  while(*p) {
    if(*p == ' ' || *p == '\t') {
        *p = '\0';
        p++;
        if(*p && *p != ' ' && *p != '\t') {
            exec_argv[++exec_argc]=p;
            assert( exec_argc <= MAX_EXEC_ARGC );
        }
    }
    p++;
  }
  debug_dv(("opt_exec=%s, argv[0]=%s, argv[1]=%s, argv[2]=%s",opt_exec, exec_argv[0], exec_argv[1], exec_argv[2]));
  
  exec_argv[exec_argc+1]=NULL;

  /* save the stderr fd because we may need it later */
  saved_stderr = dup(STDERR_FILENO);

  /* duplicate the socket for the child program */
  dup2(ncsock->fd, STDIN_FILENO);	/* the precise order of fiddlage */
  close(ncsock->fd);			/* is apparently crucial; this is */
  dup2(STDIN_FILENO, STDOUT_FILENO);	/* swiped directly out of "inetd". */
  dup2(STDIN_FILENO, STDERR_FILENO);	/* also duplicate the stderr channel */

  /* replace this process with the new one */
#ifndef USE_OLD_COMPAT  ///default method except --enable-compat
  debug_dv(("Not use old compatitiviy\n"));
  ///ncexec_argv[2]=ncexec_argv[1];
  ///ncexec_argv[1]="-c";
  ///debug_dv(("opt_exec=%s, argc=%d, argv[0]=%s, argv[1]=%s, argv[2]=%s",opt_exec, ncexec_argc, ncexec_argv[0], ncexec_argv[1], ncexec_argv[2]));
  //execl("/bin/sh", p, "-c", opt_exec, NULL);
  execl("/bin/sh", exec_name, "-c", command, NULL);
#else  
  //execl(opt_exec,p,NULL);
  execv(opt_exec, exec_argv); 
#endif
  dup2(saved_stderr, STDERR_FILENO);
  ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Couldn't execute %s: %s"),
	  opt_exec, strerror(errno));
}				/* end of ncexec() */

/* main: handle command line arguments and listening status */

int main(int argc, char *argv[])
{
  int c, glob_ret = EXIT_FAILURE;
  int total_ports, left_ports, accept_ret = -1, connect_ret = -1;
  int usec;
  int nhbrd=-1,nhbwr=-1,poll_timeout=-1;
  struct sigaction sv;
  char* argM = NULL;
  char hb_buf[8]; //heartbeat buffer
  nc_port_t local_port;		/* local port specified with -p option */
  nc_host_t local_host;		/* local host for bind()ing operations */
  nc_host_t remote_host;
  nc_sock_t listen_sock;
  nc_sock_t connect_sock;
  nc_sock_t stdio_sock;

  memset(&local_port, 0, sizeof(local_port));
  memset(&local_host, 0, sizeof(local_host));
  memset(&remote_host, 0, sizeof(remote_host));
  memset(&listen_sock, 0, sizeof(listen_sock));
  memset(&connect_sock, 0, sizeof(listen_sock));
  memset(&stdio_sock, 0, sizeof(stdio_sock));
  listen_sock.domain = PF_INET;
  connect_sock.domain = PF_INET;
///For bridge mode. added at 20210707
  nc_sock_t connect_bridge_sock;
  memset(&connect_bridge_sock, 0, sizeof(nc_sock_t));
  connect_bridge_sock.domain = PF_INET;
///for Switch mode
  nc_sock_t listen_sock2;
  memset(&listen_sock2, 0, sizeof(nc_sock_t));
  listen_sock2.domain = PF_INET;

#ifdef ENABLE_NLS
  setlocale(LC_MESSAGES, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  /* set up the signal handling system */
  sigemptyset(&sv.sa_mask);
  sv.sa_flags = SA_RESTART;
  sv.sa_handler = got_child;
  sigaction(SIGCHLD, &sv, NULL);
  sv.sa_flags = 0;
  sv.sa_handler = got_int;
  sigaction(SIGINT, &sv, NULL);
  sv.sa_handler = got_term;
  sigaction(SIGTERM, &sv, NULL);
  sv.sa_handler = got_usr1;
  sigaction(SIGUSR1, &sv, NULL);
  /* ignore some boring signals */
  sv.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sv, NULL);
  sigaction(SIGURG, &sv, NULL);

  /* if no args given at all, take them from stdin and generate argv */
  if (argc == 1)
    netcat_commandline_read(&argc, &argv);

  /* check for command line switches */
  while (TRUE) {
    int option_index = 0;
    static const struct option long_options[] = {
	{ "close",	no_argument,		NULL, 'c' },
	{ "chosen",	no_argument,		NULL, 'C' },
	{ "debug",	no_argument,		NULL, 'd' },
	{ "exec",	required_argument,	NULL, 'e' },
	{ "gateway",	required_argument,	NULL, 'g' },
	{ "pointer",	required_argument,	NULL, 'G' },
	{ "heartbeat",	no_argument,		NULL, 'H' },
	{ "help",	no_argument,		NULL, 'h' },
	{ "interval",	required_argument,	NULL, 'i' },
	{ "listen",	no_argument,		NULL, 'l' },
	{ "tunnel",	required_argument,	NULL, 'L' },
    { "multi-processes", no_argument, NULL, 'M' },
	{ "dont-resolve", no_argument,		NULL, 'n' },
	{ "output",	required_argument,	NULL, 'o' },
	{ "local-port",	required_argument,	NULL, 'p' },
	{ "tunnel-port", required_argument,	NULL, 'P' },
	{ "randomize",	no_argument,		NULL, 'r' },
	{ "source",	required_argument,	NULL, 's' },
	{ "tunnel-source", required_argument,	NULL, 'S' },
#ifndef USE_OLD_COMPAT
	{ "tcp",	no_argument,		NULL, 't' },
	{ "telnet",	no_argument,		NULL, 'T' },
#else
	{ "tcp",	no_argument,		NULL, 1 },
	{ "telnet",	no_argument,		NULL, 't' },
#endif
	{ "udp",	no_argument,		NULL, 'u' },
	{ "verbose",	no_argument,		NULL, 'v' },
	{ "version",	no_argument,		NULL, 'V' },
	{ "hexdump",	no_argument,		NULL, 'x' },
	{ "wait",	required_argument,	NULL, 'w' },
	{ "zero",	no_argument,		NULL, 'z' },
    { "bridge", required_argument, NULL, 'B'},
    { "switch", required_argument, NULL, 'A'},
    { "sig-in", required_argument, NULL, 'I'},
    { "sig-out", required_argument, NULL, 'O'},
	{ 0, 0, 0, 0 }
    };

    c = getopt_long(argc, argv, "A:B:cC:de:g:G:Hhi:I:lL:Mno:O:p:P:rs:S:tTuvVxw:z",
		    long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
    case 'A':           /* mode flag: switch mode */
      if (netcat_mode != NETCAT_UNSPEC)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("You can specify mode flags (`-A', `-B', `-l' and `-L') only once"));
      if (opt_zero)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-A' and `-z' options are incompatible"));
      do {
	    char *div = strchr(optarg, ':');

        if (div && *(div + 1))
            *div++ = '\0';
        else
            ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
                    _("Invalid target string for `-A' option"));

        if (!netcat_resolvehost(&listen_sock2.local_host, optarg))
            ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
                    _("Couldn't resolve switch local host: %s"), optarg);
        if (!netcat_getport(&listen_sock2.local_port, div, 0))
            ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
                    _("Invalid switch local port: %s"), div);

        netcat_mode = NETCAT_SWITCH;
      } while (FALSE);
      opt_eofclose = TRUE; ///force eof to exit !!
      break;
    case 'B':			/* mode flag: bridge mode */
      if (netcat_mode != NETCAT_UNSPEC)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("You can specify mode flags (`-B', `-l' and `-L') only once"));
      if (opt_zero)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-B' and `-z' options are incompatible"));

	debug_dv(("optarg:  %s", optarg));
      do {

	char *div = strchr(optarg, ':');

	if (div && *(div + 1))
	  *div++ = '\0';
	else
	  ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Invalid target string for `-B' option"));

	/* lookup the remote address and the remote port for bridging */
	if (!netcat_resolvehost(&connect_bridge_sock.host, optarg))
	  ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
	  	  _("Couldn't resolve bridge target host: %s"), optarg);
	if (!netcat_getport(&connect_bridge_sock.port, div, 0))
	  ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
	  	  _("Invalid bridge target port: %s"), div);

	netcat_mode = NETCAT_BRIDGE;
      } while (FALSE);
      opt_eofclose = TRUE; ///force eof to exit !!
      break;
    case 'c':			/* close connection on EOF from stdin */
      opt_eofclose = TRUE;
      break;
    case 'C':			/* close connection on EOF from stdin */
      opt_chosen = atoi(optarg);
      if(opt_chosen<1||opt_chosen>2)
          ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
                  _("Invalid value \"%s\", use 1 or 2"), optarg);
      break;
    case 'd':			/* enable debugging */
      opt_debug = TRUE;
      break;
    case 'e':			/* prog to exec */
      if (opt_exec)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Cannot specify `-e' option double"));
      opt_exec = strdup(optarg);
      break;
    case 'G':			/* srcrt gateways pointer val */
      break;
    case 'g':			/* srcroute hop[s] */
      break;
    case 'H':
      opt_heartbeat = TRUE;
      break;
    case 'h':			/* display help and exit */
      netcat_printhelp(argv[0]);
      exit(EXIT_SUCCESS);
    case 'i':			/* line/ports interval time (seconds) */
      opt_interval = atof(optarg);
      if (opt_interval <= 0)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Invalid interval time \"%s\""), optarg);
      break;
    case 'I':
      if (strlen(optarg)>116)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Your signature is too long"));
      opt_signature_in=optarg;
      break;
    case 'O':
      if (strlen(optarg)>116)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Your signature is too long"));
      opt_signature_out=optarg;
      break;
    case 'l':			/* mode flag: listen mode */
      if (netcat_mode != NETCAT_UNSPEC)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("You can specify mode flags (`-l' and `-L') only once"));
      netcat_mode = NETCAT_LISTEN;
      break;
    case 'L':			/* mode flag: tunnel mode */
      if (netcat_mode != NETCAT_UNSPEC)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("You can specify mode flags (`-l' and `-L') only once"));
      if (opt_zero)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-L' and `-z' options are incompatible"));
      do {
	char *div = strchr(optarg, ':');

	if (div && *(div + 1))
	  *div++ = '\0';
	else
	  ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Invalid target string for `-L' option"));

	/* lookup the remote address and the remote port for tunneling */
	if (!netcat_resolvehost(&connect_sock.host, optarg))
	  ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
	  	  _("Couldn't resolve tunnel target host: %s"), optarg);
	if (!netcat_getport(&connect_sock.port, div, 0))
	  ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
	  	  _("Invalid tunnel target port: %s"), div);

	netcat_mode = NETCAT_TUNNEL;
      } while (FALSE);
      break;
    case 'M':           ///last-listening
      opt_multi_pr = TRUE;
      if(!(argM=search_arg(argv,"-M")))
          argM=search_arg(argv,"--multi-processes");
      break;
    case 'n':			/* numeric-only, no DNS lookups */
      opt_numeric = TRUE;
      break;
    case 'o':			/* output hexdump log to file */
      opt_outputfile = strdup(optarg);
      opt_hexdump = TRUE;	/* implied */
      break;
    case 'p':			/* local source port */
      if (!netcat_getport(&local_port, optarg, 0))
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Invalid local port: %s"),
		optarg);
      break;
    case 'P':			/* used only in tunnel mode (source port) */
      if (!netcat_getport(&connect_sock.local_port, optarg, 0))
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Invalid tunnel connect port: %s"), optarg);
      break;
    case 'r':			/* randomize various things */
      opt_random = TRUE;
      break;
    case 's':			/* local source address */
      /* lookup the source address and assign it to the connection address */
      if (!netcat_resolvehost(&local_host, optarg))
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Couldn't resolve local host: %s"), optarg);
      break;
    case 'S':			/* used only in tunnel mode (source ip) */
      if (!netcat_resolvehost(&connect_sock.local_host, optarg))
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Couldn't resolve tunnel local host: %s"), optarg);
      break;
    case 1:			/* use TCP protocol (default) */
#ifndef USE_OLD_COMPAT
    case 't':
#endif
      opt_proto = NETCAT_PROTO_TCP;
      break;
#ifdef USE_OLD_COMPAT
    case 't':
#endif
    case 'T':			/* answer telnet codes */
      opt_telnet = TRUE;
      break;
    case 'u':			/* use UDP protocol */
      opt_proto = NETCAT_PROTO_UDP;
      break;
    case 'v':			/* be verbose (twice=more verbose) */
      opt_verbose++;
      break;
    case 'V':			/* display version and exit */
      netcat_printversion();
      exit(EXIT_SUCCESS);
    case 'w':			/* wait time (in seconds) */
      opt_wait = atoi(optarg);
      if (opt_wait <= 0)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Invalid wait-time: %s"),
		optarg);
      break;
    case 'x':			/* hexdump traffic */
      opt_hexdump = TRUE;
      break;
    case 'z':			/* little or no data xfer */
      if (netcat_mode >= NETCAT_TUNNEL)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-L' and `-z' options are incompatible"));
      opt_zero = TRUE;
      break;
    default:
      ncprint(NCPRINT_EXIT, _("Try `%s --help' for more information."), argv[0]);
    }
  }

  if (opt_zero && opt_exec)
    ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-e' and `-z' options are incompatible"));

  if ((netcat_mode < NETCAT_TUNNEL || opt_proto != NETCAT_PROTO_TCP) && opt_multi_pr)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-M|--multi-processes' only used with `-L|--tunnel',`-A|--switch',`-B|--bridge' and `-t'"));

  if ((netcat_mode <= NETCAT_TUNNEL || opt_proto != NETCAT_PROTO_TCP || !opt_multi_pr) && opt_heartbeat)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-H|--heartbeat' only used with `-A|--switch',`-B|--bridge', -M|--multi-processes and `-t'"));

  /* initialize the flag buffer to keep track of the specified ports */
  netcat_flag_init(65535);

#ifndef DEBUG
  /* check for debugging support */
  if (opt_debug)
    ncprint(NCPRINT_WARNING,
	    _("Debugging support not compiled, option `-d' discarded. Using maximum verbosity."));
#endif

  /* randomize only if needed */
  if (opt_random)
#ifdef USE_RANDOM
    SRAND(time(0));
#else
    ncprint(NCPRINT_WARNING,
	    _("Randomization support not compiled, option `-r' discarded."));
#endif

  /* handle the -o option. exit on failure */
  if (opt_outputfile) {
    output_fp = fopen(opt_outputfile, "w");
    if (!output_fp)
      ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Failed to open output file: %s"),
	      strerror(errno));
  }
  else
    output_fp = stderr;

  debug_v(("Trying to parse non-args parameters (argc=%d, optind=%d)", argc,
	  optind));

  /* try to get an hostname parameter */
  if (optind < argc) {
    char *myhost = argv[optind++];
    if (!netcat_resolvehost(&remote_host, myhost))
      ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Couldn't resolve host \"%s\""),
	      myhost);
  }

  /* now loop all the other (maybe optional) parameters for port-ranges */
  while (optind < argc) {
    const char *get_argv = argv[optind++];
    char *q, *parse = strdup(get_argv);
    int port_lo = 0, port_hi = 65535;
    nc_port_t port_tmp;

    if (!(q = strchr(parse, '-')))	/* simple number? */
      q = strchr(parse, ':');		/* try with the other separator */

    if (!q) {
      if (netcat_getport(&port_tmp, parse, 0))
	netcat_flag_set(port_tmp.num, TRUE);
      else
	goto got_err;
    }
    else {		/* could be in the forms: N1-N2, -N2, N1- */
      *q++ = 0;
      if (*parse) {
	if (netcat_getport(&port_tmp, parse, 0))
	  port_lo = port_tmp.num;
	else
	  goto got_err;
      }
      if (*q) {
	if (netcat_getport(&port_tmp, q, 0))
	  port_hi = port_tmp.num;
	else
	  goto got_err;
      }
      if (!*parse && !*q)		/* don't accept the form '-' */
	goto got_err;

      /* now update the flagset (this is int, so it's ok even if hi == 65535) */
      while (port_lo <= port_hi)
	netcat_flag_set(port_lo++, TRUE);
    }

    free(parse);
    continue;

 got_err:
    free(parse);
    ncprint(NCPRINT_ERROR, _("Invalid port specification: %s"), get_argv);
    exit(EXIT_FAILURE);
  }

  debug_dv(("Arguments parsing complete! Total ports=%d", netcat_flag_count()));
#if 0
  /* pure debugging code */
  c = 0;
  while ((c = netcat_flag_next(c))) {
    printf("Got port=%d\n", c);
  }
  exit(0);
#endif
    
    if (netcat_mode == NETCAT_SWITCH) ///need local port specified
        if (local_port.num==0)
      ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("No local port specified. "));
  /* Handle listen, tunnel and switch mode(whose index number is higher) */
  if (netcat_mode > NETCAT_CONNECT && netcat_mode < NETCAT_BRIDGE) {
    /* in tunnel mode the opt_zero flag is illegal, while on listen mode it
       means that no connections should be accepted.  For UDP it means that
       no remote addresses should be used as default endpoint, which means
       that we can't send anything.  In both situations, stdin is no longer
       useful, so close it. */
    if (opt_zero) {
      close(STDIN_FILENO);
      use_stdin = FALSE;
    }

    /* prepare the socket var and start listening */
    listen_sock.proto = opt_proto;
    listen_sock.timeout = opt_wait;
    memcpy(&listen_sock.local_host, &local_host, sizeof(listen_sock.local_host));
    memcpy(&listen_sock.local_port, &local_port, sizeof(listen_sock.local_port));
    memcpy(&listen_sock.host, &remote_host, sizeof(listen_sock.host));
RELISTEN:  ///for multi-processes tunnel & switch
    accept_ret = core_listen(&listen_sock);

    /* in zero I/O mode the core_tcp_listen() call will always return -1
       (ETIMEDOUT) since no connections are accepted, because of this our job
       is completed now. */
    if (accept_ret < 0) {
      /* since i'm planning to make `-z' compatible with `-L' I need to check
         the exact error that caused this failure. */
      if (opt_zero && (errno == ETIMEDOUT))
	exit(0);

      ncprint(NCPRINT_VERB1 | NCPRINT_EXIT, _("Listen mode failed: %s"),
	      strerror(errno));
    }

    /* in verification mode */
    if (opt_signature_in && opt_chosen!=2 && !verify_signature(listen_sock.fd))
        goto RELISTEN;

    /* in switch mode, listen on both ports, exchange data */
    if (netcat_mode == NETCAT_SWITCH) {
        listen_sock2.proto = opt_proto;
        listen_sock2.timeout = opt_wait;
        int nlfd;
        struct pollfd spfds[2];
RELISTEN2:
        memset(spfds, 0, 2*sizeof(struct pollfd));
        spfds[0].fd=listen_sock.fd;
        spfds[0].events=POLLRDHUP|POLLHUP|POLLERR|POLLNVAL;
        spfds[1].fd=listen_sock2.lfd ? listen_sock2.lfd : 
            netcat_socket_new_listen(PF_INET, &listen_sock2.local_host.iaddrs[0],
			listen_sock2.local_port.netnum);
        listen_sock2.lfd=spfds[1].fd;
        spfds[1].events=POLLIN|POLLERR|POLLNVAL;
        if(opt_heartbeat)poll_timeout=HEARTBEAT_INTERVAL;
        nlfd = poll(spfds,2,poll_timeout);
        while (nlfd < 0) {
            if (errno != EINTR) {
                ncprint(NCPRINT_ERROR | NCPRINT_EXIT, 
                    "Critical system request failed: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }
            nlfd = poll(spfds,2,poll_timeout);
        }
        if(spfds[0].revents) { ///connection of sock1 broken when sock2 listen
            debug_v(("Assume socket 1 closed"));
            close(listen_sock.fd);
            listen_sock.fd=0;
            goto RELISTEN;
        }
        if(spfds[1].revents & (POLLERR|POLLNVAL)) {
            debug_v(("Poll() error event"));
            close(listen_sock2.lfd);
            listen_sock2.lfd=0;
            goto RELISTEN2;
        }
        if(opt_multi_pr && opt_heartbeat && !nlfd) {
            write(listen_sock.fd,HEARTBEAT_MSG,HEARTBEAT_MSG_LEN);
            goto RELISTEN2;
        }

        accept_ret = core_listen(&listen_sock2);
        if (accept_ret < 0) {
          if (opt_zero && (errno == ETIMEDOUT))
            exit(0);
      ncprint(NCPRINT_VERB1 | NCPRINT_EXIT, _("Second listen failed: %s"),
            strerror(errno));
        }
        if (opt_signature_in && opt_chosen!=1 && !verify_signature(listen_sock2.fd))
            goto RELISTEN2;
        if(opt_multi_pr) {
      assert(netcat_mode == NETCAT_SWITCH);
            switch(fork()) {
                case 0:
                    close(listen_sock.lfd); ///In Child, Unneeded copy of listening socket
                    close(listen_sock2.lfd);
                    listen_sock.lfd=0;
                    listen_sock2.lfd=0;
                    memset(argM,0,strlen(argM)); ///remove -M to mark subprocess in /proc
                    break;
                default:
                    close(listen_sock.fd);	///In Parent, Unneeded copy of accepted socket 
                    close(listen_sock2.fd);
                    listen_sock.fd=0;
                    listen_sock2.fd=0;
                    goto RELISTEN;
            }
        /* handle if no data read from sock2 after accept */
            memset(spfds, 0, 2*sizeof(struct pollfd));
            spfds[0].fd=listen_sock.fd;
            spfds[0].events=POLLRDHUP|POLLHUP|POLLERR|POLLNVAL;
            spfds[1].fd=listen_sock2.fd;
            spfds[1].events=POLLIN|POLLERR|POLLNVAL;
#define READ_TIMEOUT 5000
            nlfd = poll(spfds,2,READ_TIMEOUT); ///read timedout after 5 seconds
            while (nlfd < 0) {
                if (errno != EINTR) {
                    ncprint(NCPRINT_ERROR | NCPRINT_EXIT, 
                            "Critical system request failed: %s", strerror(errno));
                    exit(EXIT_FAILURE);
                }
                nlfd = poll(spfds,2,READ_TIMEOUT);
            }
            if(!nlfd || spfds[0].revents || (spfds[1].revents & (POLLERR|POLLNVAL))) {
                if(!nlfd)debug_v(("Read timedout"));
                if(spfds[0].revents) debug_v(("Remote socket 1 closed"));
                if(spfds[1].revents & (POLLERR|POLLNVAL)) debug_v(("Poll() error event"));
                close(listen_sock.fd);
                close(listen_sock2.fd);
                goto main_exit;
            }
        }
        core_readwrite(&listen_sock, &listen_sock2);
        debug_dv(("Switch: EXIT"));
        goto main_exit;
    }

    /* if we are in listen mode, run the core loop and exit when it returns.
       otherwise now it's the time to connect to the target host and tunnel
       them together (which means passing to the next section. */
    if (netcat_mode == NETCAT_LISTEN) {
      if (opt_exec) {
	ncprint(NCPRINT_VERB2, _("Passing control to the specified program"));
	ncexec(&listen_sock);		/* this won't return */
      }
      core_readwrite(&listen_sock, &stdio_sock);
      debug_dv(("Listen: EXIT"));
    }
    else {
      /* otherwise we are in tunnel mode.  The connect_sock var was already
         initialized by the command line arguments. */
	    connect_sock.proto = opt_proto;
        connect_sock.timeout = opt_wait;
        if(opt_multi_pr) {
            switch(fork()) {
                case 0:
                    close(listen_sock.lfd); ///In Child, Unneeded copy of listening socket
                    memset(argM,0,strlen(argM));
                    break;
                default:
                    close(listen_sock.fd);	///In Parent, Unneeded copy of accepted socket 
                    listen_sock.fd=0;
                    goto RELISTEN;
                    break;
            }
        }
      assert(netcat_mode == NETCAT_TUNNEL);
      connect_ret = core_connect(&connect_sock);

      /* connection failure? (we cannot get this in UDP mode) */
      if (connect_ret < 0) {
	assert(opt_proto != NETCAT_PROTO_UDP);
	ncprint(NCPRINT_VERB1, "%s: %s",
		netcat_strid(&connect_sock.host, &connect_sock.port),
		strerror(errno));
      } else {
          if(opt_signature_out)
              send_signature(connect_sock.fd);
          glob_ret = EXIT_SUCCESS;
          core_readwrite(&listen_sock, &connect_sock);
    debug_dv(("Tunnel: EXIT (ret=%d)", glob_ret));
      }
    }
    /* all jobs should be ok, go to the cleanup */
    goto main_exit;
  }				/* end of listen and tunnel mode handling */

  /* we need to connect outside, this is the connect mode */
  if(netcat_mode == NETCAT_UNSPEC)
  netcat_mode = NETCAT_CONNECT;

  /* first check that a host parameter was given */
  if (!remote_host.iaddrs[0].s_addr) {
    /* FIXME: The Networking specifications state that host address "0" is a
       valid host to connect to but this broken check will assume as not
       specified. */
    ncprint(NCPRINT_NORMAL, _("%s: missing hostname argument"), argv[0]);
    ncprint(NCPRINT_EXIT, _("Try `%s --help' for more information."), argv[0]);
  }

  /* since ports are the second argument, checking ports might be enough */
  total_ports = netcat_flag_count();
  if (total_ports == 0)
    ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
	    _("No ports specified for connection"));

  c = 0;			/* must be set to 0 for netcat_flag_next() */
  left_ports = total_ports;
  while (left_ports > 0) {
    /* `c' is the port number independently of the sorting method (linear
       or random).  While in linear mode it is also used to fetch the next
       port number */
    if (opt_random)
      c = netcat_flag_rand();
    else
      c = netcat_flag_next(c);
    left_ports--;		/* decrease the total ports number to try */

    /* since we are nonblocking now, we can start as many connections as we want
       but it's not a great idea connecting more than one host at time */
    connect_sock.proto = opt_proto;
    connect_sock.timeout = opt_wait;
    memcpy(&connect_sock.local_host, &local_host,
	   sizeof(connect_sock.local_host));
    memcpy(&connect_sock.local_port, &local_port,
	   sizeof(connect_sock.local_port));
    memcpy(&connect_sock.host, &remote_host, sizeof(connect_sock.host));
    netcat_getport(&connect_sock.port, NULL, c);

    /* FIXME: in udp mode and NETCAT_CONNECT, opt_zero is senseless */
RECONNECT:
    connect_ret = core_connect(&connect_sock);

    /* connection failure? (we cannot get this in UDP mode) */
    if (netcat_mode == NETCAT_CONNECT && connect_ret < 0) {
      int ncprint_flags = NCPRINT_VERB1;
      assert(connect_sock.proto != NETCAT_PROTO_UDP);

      /* if we are portscanning or multiple connecting show only open
         ports with verbosity level 1. */
      if (total_ports > 1)
	ncprint_flags = NCPRINT_VERB2;

      ncprint(ncprint_flags, "%s: %s",
	      netcat_strid(&connect_sock.host, &connect_sock.port),
	      strerror(errno));
      continue;			/* go with next port */
    }
    if(netcat_mode==NETCAT_CONNECT && opt_signature_out)
        send_signature(connect_sock.fd);

    /* when portscanning (or checking a single port) we are happy if AT LEAST
       ONE port is available. */
    glob_ret = EXIT_SUCCESS;

    if(netcat_mode == NETCAT_BRIDGE) {
    /* otherwise we are in bridge mode(only connect first port). The connect_bridge_sock 
          is already initialized by command line arguments. */
        
	    assert(opt_proto != NETCAT_PROTO_UDP); ///not available with udp
        while(connect_ret < 0){  ///if remote host not ready, don't exit!
            int ncprint_flags = NCPRINT_VERB1;
            ncprint(ncprint_flags, "%s: %s",
                    netcat_strid(&connect_sock.host, &connect_sock.port),
                    strerror(errno));
            sleep(5);  ///reconnect interval
            connect_ret = core_connect(&connect_sock);
        }
        if(opt_signature_out && opt_chosen!=2)
            send_signature(connect_sock.fd);
        connect_bridge_sock.proto = opt_proto;
        connect_bridge_sock.timeout = opt_wait;
        if(opt_multi_pr) {
            int nrdfd;
            struct pollfd spfd;
HBREPOLL:   memset(&spfd,0,sizeof(struct pollfd));
            spfd.fd=connect_sock.fd;
            spfd.events=POLLIN|POLLRDHUP|POLLHUP|POLLERR|POLLNVAL;
         /* use poll instead of select to detect remote close */
            if(opt_heartbeat)poll_timeout = HEARTBEAT_INTERVAL * 3; //after 15s without heatbeat message
            nrdfd = poll(&spfd,1,poll_timeout);
            while (nrdfd < 0) {
                if (errno != EINTR) {
                    ncprint(NCPRINT_ERROR, "Critical system request failed: %s", strerror(errno));
                    close(connect_sock.fd);
                    connect_sock.fd=0;
                    goto RECONNECT;
                }
                nrdfd = poll(&spfd,1,poll_timeout);
            }
            if(spfd.revents & (POLLRDHUP|POLLHUP|POLLERR|POLLNVAL)||
                    (opt_heartbeat && !nrdfd)) { //poll timed out
                debug_v(("Remote socket closed"));
                close(connect_sock.fd);
                connect_sock.fd=0;
                goto RECONNECT;
            }
            if(opt_heartbeat) {
                memset(hb_buf,0,8);
                nhbrd=read(connect_sock.fd,hb_buf,HEARTBEAT_MSG_LEN); //expect NETCAT!!
                if(!strncmp(hb_buf,HEARTBEAT_MSG,HEARTBEAT_MSG_LEN))
                    goto HBREPOLL;
            }
        /* fork only if we have something read */
            if(fork()) {
                close(connect_sock.fd);
                connect_sock.fd=0;
                goto RECONNECT;
            }
            memset(argM,0,strlen(argM));
        }

        connect_ret = core_connect(&connect_bridge_sock);
        /* connection failure? (we cannot get this in UDP mode) */
        if (connect_ret < 0) {
            assert(opt_proto != NETCAT_PROTO_UDP);
            ncprint(NCPRINT_VERB1, "%s: %s",
                    netcat_strid(&connect_bridge_sock.host, &connect_bridge_sock.port),
                    strerror(errno));
        } else {
            if(opt_signature_out && opt_chosen!=1)
                send_signature(connect_bridge_sock.fd);
            glob_ret = EXIT_SUCCESS;
            if(opt_heartbeat) {
                nhbwr=write(connect_bridge_sock.fd,hb_buf,nhbrd); ///here we have 8 bytes data already read
                if(nhbwr<nhbrd) {
            ncprint(NCPRINT_VERB1, "%s: %s",
                    netcat_strid(&connect_bridge_sock.host, &connect_bridge_sock.port),
                    strerror(errno));
                    exit(EXIT_FAILURE);
                }
            }
            core_readwrite(&connect_bridge_sock, &connect_sock);
            debug_dv(("Bridge child: EXIT (ret=%d)", glob_ret));
        }
        goto main_exit;
    }

    if (opt_zero) {
      shutdown(connect_ret, 2);
      close(connect_ret);
    }
    else {
      if (opt_exec) {
	ncprint(NCPRINT_VERB2, _("Passing control to the specified program"));
	ncexec(&connect_sock);		/* this won't return */
      }
      core_readwrite(&connect_sock, &stdio_sock);
      /* FIXME: add a small delay */
      debug_v(("Connect: EXIT"));

      /* both signals are handled inside core_readwrite(), but while the
         SIGINT signal is fully handled, the SIGTERM requires some action
         from outside that function, because of this that flag is not
         cleared. */
      if (got_sigterm)  ///got term in core_readwrite()
	break;
    }
      sleep((unsigned int)opt_interval);
      usec=(opt_interval-(unsigned int)opt_interval)*1000000;
      usleep(usec);
  }			/* end of while (left_ports > 0) */

  /* all basic modes should return here for the final cleanup */
 main_exit:
  debug_v(("Main: EXIT (cleaning up)"));

  netcat_printstats(FALSE);
  return glob_ret;
}				/* end of main() */
