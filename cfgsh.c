/*
 *	cfgsh 1.1.2
 * 	
 Copyright (C) 2003 Gilad Ben-Yossef <gilad@benyossef.com>
 Copyright (C) 2004 Codefidence Ltd. http://www.codefidence.com
 Copyright (C) 2005 Ami Chayun <ami@beyondsecurity.com>

 This work is heavily based on the fileman.c example distributed with
 the GNU readline library and uses the library for all text lines
 reading and manipulation. The GNU readline library is under the 
 following copyright:

 Copyright (C) 1987, 1989, 1992 Free Software Foundation, Inc.

 The get_name and find_ifs (originally if_readlist_proc) functions were 
 copied from Busybox's libbb, file interface.c which holds the following 
 copyright notice:

 "stolen from net-tools-1.59 and stripped down for busybox by
 Erik Andersen <andersen@codepoet.org>
 
 Heavily modified by Manuel Novoa III       Mar 12, 2001
  
 Version:     $Id$
  
 Author:      Fred N. van Kempen, <waltje@uwalt.nl.mugnet.org>
 and others.  Copyright 1993 MicroWalt Corporation
  
 {1.34} - 19980630 - Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 - gettext instead of catgets for i18n
 10/1998  - Andi Kleen. Use interface list primitives.
 20001008 - Bernd Eckenfels, Patch from RH for setting mtu
 (default AF was wrong)"
     
 This file is part of cfgsh -- A simple configuration 'shell' 
 for embedded systems. It gives an embedded system user a limited
 interface for configuring basic system properties in an easy 
 manner, with context sensative help and history managment.
   
 cfgsh is free software; you can redistribute it and/or modify 
 it under the terms of the GNU General Public License version 2 as 
 published by the Free Software Foundation; 

 cfgsh is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of 
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 The GNU General Public License is often shipped with GNU software, and
 is generally kept in a file called COPYING or LICENSE.  If you do not
 have a copy of the license, write to the Free Software Foundation,
 59 Temple Place, Suite 330, Boston, MA 02111 USA. 

*/

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "cfgsh.h"

static char const rcsid[] = "(C) 2005 Codefidence Ltd. $Id$";

COMMAND root_commands[] = {

  { "role", com_role, "Display or set system role: role [role]", path_completion_matches, ROLES_PATH},
  { "timezone", com_tz, "Display or set time zone: timezone [time zone]", path_completion_matches, ZONES_PATH},
  { "network", com_net, "Enter network configuration mode: network", NULL, NULL},
  { "ping", com_ping, "Ping destination: ping  <hostname | address>", NULL, NULL},
  { "hostname", com_hostname, "Displays or set the host name: hostname [name]", NULL, NULL},
  { "halt", com_halt, "Shutdown", NULL, NULL},
  { "reboot", com_reboot, "Reboot", NULL, NULL},
  { "show", com_show, "Display settings: show [" SHOW_OPT_CONFIG "|" SHOW_OPT_INTERFACES "|" SHOW_OPT_ROUTES " |" SHOW_OPT_RESOLVER "]", show_completion_matches, NULL},
  { "save", com_save, "Save configuration" , NULL, NULL},
  { "exit", com_quit, "Logout", NULL, NULL},
  { "quit", com_quit, "Logout", NULL, NULL},
  { "help", com_help, "Display this text" , NULL, NULL},
  { (char *)NULL, (rl_icpfunc_t *)NULL, (char *)NULL, (complete_func_t *)NULL, (char *)NULL}
};

COMMAND network_commands[] = {
  { "interface", com_int, "Set active network interfaces: interface [interface name]", interface_completion_matches, NULL},
  { "route", com_route, "Enter route configuration mode: route [priority]", NULL, NULL},
  { "default", com_gw, "Display or set default gateway address: gateway [address]", NULL, NULL},
  { "resolver", com_nameservers, "Enter domain name resolution configuration mode: resolver", NULL, NULL},
  { "exit", com_root, "Return to root mode", NULL, NULL},
  { "quit", com_quit, "Logout", NULL, NULL},
  { "help", com_help, "Display this text" , NULL, NULL},
  { (char *)NULL, (rl_icpfunc_t *)NULL, (char *)NULL, (complete_func_t *)NULL, (char *)NULL}
};

COMMAND nameservers_commands[] = {
  { "primary", com_ns, "Display or set primary name server address: primary [address]", NULL, NULL},
  { "secondary", com_ns2, "Display or set secondary name server address: secondary [address]", NULL, NULL},
  { "search", com_search, "Display or domain search: search [domain]", NULL, NULL},
  { "exit", com_net, "Return to network mode", NULL, NULL},
  { "quit", com_quit, "Logout", NULL, NULL},
  { "help", com_help, "Display this text" , NULL, NULL},
  { (char *)NULL, (rl_icpfunc_t *)NULL, (char *)NULL, (complete_func_t *)NULL, (char *)NULL}
};

COMMAND route_commands[] = {
  { "set", com_set_route, "Sets current route: set [network] [netmask] [device] <gateway>", route_completion_matches, NULL},
  { "delete", com_del_route, "Delete current route: delete", NULL, NULL},
  { "show", com_show_route, "Show current route: show", NULL, NULL},
  { "exit", com_net, "Return to network mode", NULL, NULL},
  { "quit", com_quit, "Logout", NULL, NULL},
  { "help", com_help, "Display this text" , NULL, NULL},
  { (char *)NULL, (rl_icpfunc_t *)NULL, (char *)NULL, (complete_func_t *)NULL, (char *)NULL}
};

COMMAND interface_commands[] = {
  { "ip", com_ip, "Display or set IP address: ip [address]", NULL, NULL},
  { "netmask", com_netmask, "Display or set network mask: netmask [address]", NULL, NULL},
  { "broadcast", com_broadcast, "Display or set broadcast address: broadcast [address|auto]", NULL, NULL},
  { "dhcp", com_dhcp, "Display or set use of DHCP: dhcp [" DHCP_OPT_ON "|" DHCP_OPT_IPONLY "|" DHCP_OPT_OFF "]", dhcp_completion_matches, NULL},
  { "exit", com_net, "Return to network mode", NULL, NULL },
  { "quit", com_quit, "Logout", NULL, NULL},
  { "help", com_help, "Display this text" , NULL, NULL },
  { (char *)NULL, (rl_icpfunc_t *)NULL, (char *)NULL, (complete_func_t *)NULL, (char *)NULL}
};

char * show_options[] = { SHOW_OPT_CONFIG, SHOW_OPT_INTERFACES, SHOW_OPT_ROUTES, SHOW_OPT_RESOLVER, NULL};
char * dhcp_options[] = { DHCP_OPT_ON, DHCP_OPT_OFF, DHCP_OPT_IPONLY , NULL};


static CONF * conf;

/* The name of this program, as taken from argv[0]. */
static char *progname;

/* When non-zero, this global means the user is done using this program. */
static int done;

/* State file descriptor */
static int conf_fd;

/* The command valid in the current context */
static COMMAND * commands = root_commands;

/* The prompt line */
static char prompt[PROMPT_SIZE];

/* Current interface */
unsigned int current_ifr;
char ifrname[IFNAMESIZ];

/* Current route */
unsigned int current_route;

/* show prompt and online help? */
static int show_prompt = 1;


/* **************************************************************** */
/*                                                                  */
/*                       Utility Functions                          */
/*                                                                  */
/* **************************************************************** */

/* A safe(r) replacement to strcmp (if used wisely) */
inline int checkarg(const char *uarg, const char *carg)
{
  return (!strncmp(uarg, carg, strlen(carg) + 1));
}
/* Return the number of the current word in the command line */
int word_num(int start, char * text)
{

  char in_word = 0;
  int word_count = 0;
  char *p = text;
  char * search_to = (text + start);

  while((p != 0) && (p != search_to)) {

    if(whitespace(*p)) {
      if(in_word) {
	word_count++;
	in_word = 0;
      }
    } else if(!in_word)
      in_word=1;
    
    p++;
  }
  
  return word_count;
  
}

/* Set the prompt */
void set_prompt(char * prompt_add) {
#ifdef PROMPT_STRING
char *prompt_string = PROMPT_STRING;
#else
char *prompt_string = conf->hostname;
#endif

  if(prompt_add)
    snprintf(prompt, PROMPT_SIZE, "%s %s%s", prompt_string, prompt_add, PROMPT);
  else
    snprintf(prompt, PROMPT_SIZE, "%s%s", prompt_string, PROMPT);

  return;
}

/* init_config */
int init_config (int setup) {

  
  if((conf_fd = shm_open(STATE_PATH, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0) {
    
    return errno;

  } 

  ftruncate(conf_fd, sizeof(CONF));

  if((conf =  mmap(0, sizeof(CONF), (PROT_READ | PROT_WRITE), MAP_SHARED, conf_fd, 0)) == MAP_FAILED) {
    
    return errno;

  }

  if(setup)  {
    unsigned int i;

    memset(conf, 0, sizeof(CONF));
    gethostname(conf->hostname,  HOST_NAME_MAX);
    conf->num_ifs = find_ifs();

    strcpy(conf->tz, "none");

  for(i=0; i<conf->num_ifs; i++) {
    strcpy(conf->dhcp[i], "off");
    strcpy(conf->ip[i], "none");
    strcpy(conf->nmask[i], "none");
    strcpy(conf->bcast[i], "none");
  }

    strcpy(conf->gw, "none");

  for(i=0; i<ROUTE_NUM; i++) {
    strcpy(conf->route[i], "none");
  }

  strcpy(conf->ns1, "none");
  strcpy(conf->ns2, "none");
  strcpy(conf->ns_search, "none");

  strcpy(conf->role, "none");

  }

  return 0;
 
}

/* parse device name from /proc/net/dev */
static char *get_name(char *name, char *p)
{
  while (isspace(*p))
    p++;
  while (*p) {
    if (isspace(*p))
      break;
    if (*p == ':') {        /* could be an alias */
      char *dot = p, *dotname = name;
      
      *name++ = *p++;
      while (isdigit(*p))
	*name++ = *p++;
      if (*p != ':') {        /* it wasn't, backup */
	p = dot;
	name = dotname;
      }
      if (*p == '\0')
	return NULL;
      p++;
      break;
    }
    *name++ = *p++;
  }
  *name++ = '\0';
  return p;
}


int find_ifs(void) {

  FILE * dev_file = NULL;
  unsigned int i = 0;
  unsigned char buf[MAX_BUF_SIZE];

  if(!( dev_file = fopen(PROC_NET_DEV, "r")))
    {
      printf("Failed to open %s file %s\n", PROC_NET_DEV, strerror(errno));
      exit(1);
    }


  fgets(buf, sizeof buf, dev_file);     /* eat line */
  fgets(buf, sizeof buf, dev_file);

  while (fgets(buf, sizeof(buf), dev_file)) {
    char name[MAX_BUF_SIZE];
 
    get_name(name, buf);
     
    if( !strncmp(name, IFNAMEBASE, 3)) i++; /* Get only interfaces starting with 'eth' */
  }

  fclose(dev_file);

  printf("Found %d Ethernet interfaces\n", i);
  return i;

}


/* Resolve a hostname (or dotted quad style address) into a sockaddr struct */

int resolve(struct sockaddr_in * sockaddr, char * host_name) {

  struct hostent * host;

  if((!sockaddr) || (!host_name))
    return EFAULT;

  if(!(host = gethostbyname(host_name))) {

    switch(h_errno) {

    case HOST_NOT_FOUND:
      return ENOENT;

    case TRY_AGAIN:
      return EAGAIN;

    default:
      return EINVAL;
    }
  }

  sockaddr->sin_family = host->h_addrtype;
  memcpy(&sockaddr->sin_addr, host->h_addr, host->h_length);

  return 0;
}


int
get_if_flags(char * if_name, short * flags) {

  struct ifreq ifr;
  int sock, ret = 0;
  
  if((!if_name) || (!flags))
    return EFAULT;
  
  if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0 )
    return errno;
  
  strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

  if(ioctl(sock, SIOCGIFFLAGS , &ifr) >= 0) {

    ret = 0;
    *flags = ifr.ifr_flags;

  } else {

    ret = errno;

  }

  close(sock);
  return ret;

}


int
set_if_flags(char * if_name, short flags) {

  struct ifreq ifr;
  int sock, ret = 0;
  
  if((!if_name) || (!flags))
    return EFAULT;
  
  if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0 )
    return errno;
  
  strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

  if((ret = ioctl(sock, SIOCGIFFLAGS, &ifr)) < 0) {
    ret = errno;
    goto out;
  }

  ifr.ifr_flags |= flags;
  
  if(ioctl(sock,  SIOCSIFFLAGS, &ifr) < 0) {
    ret = errno;
  }

 out:

  close(sock);
  return ret;
  
}

int
set_numeric_ip(char * if_name, struct sockaddr_in * sockaddr, ADDR_SET_OPS operation) {

  struct ifreq ifr;
  int sock, ret = 0;
  
  if((!if_name) || (!sockaddr)) {
    ret = EFAULT;
    goto out;
  }

  if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
    ret = errno;
    goto out;
  }
  
  memcpy(&ifr.ifr_addr, sockaddr, sizeof(struct sockaddr));
  strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
  
  if((ret = ioctl(sock, operation , &ifr)) != 0) {
    ret = errno;
  } 
  
  close(sock);

 out:
  return ret;

}

/* A helper function to set one of the interfcace addresses,
   be it the IP, netmask or broadcast. It also sets the out_address
   to the dotted quad form of the address. out_address must be a least 
   of IPQUADSIZ length. */

int
set_if_address(char * if_name, char * in_address, ADDR_SET_OPS operation, char * out_address) {

  struct sockaddr_in sockaddr;
  int ret = 0;

  if((!if_name) || (!in_address) || (!out_address)) {
    ret = EFAULT;
    goto out;
  }  

  set_if_flags(if_name, IFF_UP);

  if( (ret = resolve(&sockaddr, in_address)) != 0 )
    goto out;

  /* With DHCP working we want to change the active config but not the system */
  if(conf->dhcp_is_on[current_ifr]) 
    goto ok; 
  
  if((ret = set_numeric_ip(if_name, &sockaddr, operation)) != 0) {
    goto out;
  } 

 ok:
  snprintf(out_address, IPQUADSIZ, "%d.%d.%d.%d", NIPQUAD(sockaddr.sin_addr));

 out:
  return ret;
}

/* A helper function to get one of the interfcace addresses,
   be it the IP, netmask or broadcast in dotted quad notation.
   address must point to a buffer of at least DQUADSIZ size */

int
get_if_address(char * if_name, char * address, ADDR_GET_OPS operation) {

  struct ifreq ifr;
  int sock, ret;

  if((!if_name) || (!address))
    return EFAULT;

  if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0 )
    return errno;
  
  strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
  
  if(ioctl(sock, operation , &ifr) >= 0) {

    struct sockaddr_in * sadr = (struct sockaddr_in *)&ifr.ifr_addr;

    ret = 0;
    snprintf(address, IPQUADSIZ, "%d.%d.%d.%d", NIPQUAD(sadr->sin_addr));

  } else {

    ret = errno;
  }

  close(sock);
  return ret;
}
  
/* Support function to automatically set the broadcast address */
int auto_broadcast(unsigned int ifr) {

  struct sockaddr_in sock;
  int ip, nmask, bcast;
  int ret;
  char ifrname[IFNAMESIZ];

  if( (ret = resolve(&sock, conf->ip[ifr])) != 0 ) {
    goto out;
  }
  memcpy(&ip, &sock.sin_addr, sizeof(ip));

  snprintf(ifrname, IFNAMESIZ, "%s%d", IFNAMEBASE, ifr);

  if( (ret = resolve(&sock, conf->nmask[ifr])) != 0 ) {
    goto out;
  }
  memcpy(&nmask, &sock.sin_addr, sizeof(nmask));

  bcast = ip | (~nmask);

  memcpy(&sock.sin_addr, &bcast, sizeof(bcast));

  ret = set_numeric_ip(ifrname, &sock, SET_BROADCAST);

 out:
  return ret;

}

int write_resolver(char *ns1, char *ns2, char * search)
{

  FILE * file;
  int ret = 0;

  /* FIX ME: use a random name here and check for existence! */

  if(! (file = fopen(RESOLV_PATH".tmp", "w"))) {
    ret = errno;
    goto out;
  }
  
  fprintf(file, "; generated by %s\n", progname);

  if(! checkarg(search, "none"))
    fprintf(file, "search %s\n", search);

  if(! checkarg(ns1, "none"))
    fprintf(file, "nameserver %s\n", ns1);

  if(! checkarg(ns2, "none"))
    fprintf(file, "nameserver %s\n", ns2);
  
  fclose(file);
  
  
  ret = commit_file(RESOLV_PATH".tmp", RESOLV_PATH);
  
 out:
  return ret;
  
}


/* A safe(r) replacement for the system() call */

int safesystem (char * filename, char * cmdline[])
{
  int pid;
  int status;

  pid = fork();

  if (pid < 0) {
    perror(cmdline[0]);
  } else if(pid == 0) {
    execve(filename, cmdline, NULL);
    /* wtf? execve just failed on us */
    exit(1);
  }

  /* FIXME: use waitpid instead so that if some other child retunrs
     we'll not get confused. Doesn't really matter for our use here. */

  wait(&status);

  if(WIFEXITED(status))
    return WEXITSTATUS(status);

  return -1;

}


char *
dupstr (s)
     char *s;
{
  char *r;

  r = xmalloc (strlen (s) + 1);
  strcpy (r, s);
  return (r);
}


/* Print usage information and exit */

void
usage(char * name) {

  printf("cfgsh - The Configuration Shell utility.\n"); 
  printf("Copyright 2002 Gilad Ben-Yossef <gilad@benyossef.com>\n"); 
  printf("Copyright 2005 Codefidence Ltd. http://codefidence.con\n\n");
  printf("Copyright 2005 Ami Chayun <ami@beyondsecurity.com> \n\n");
  printf("Usage: %s [option]\n\n", name); 
  printf("Options:\n"); 
  printf("  setup  - Setup system on boot from configuration file.\n"); 
  printf("  clean  - Reset internal state to default values.\n           Does not change the system state.\n"); 
  printf("  silent - Work normally, but don't display prompt.\n           Good for use from scripts.\n"); 

  exit(0);

}

void dump_config(FILE * file) {

  unsigned int i;
  if(!file) return;

  fprintf(file, "# Configuration Shell config file\n");

  
  fprintf(file, "hostname %s\n", conf->hostname);
  fprintf(file, "timezone %s\n", conf->tz);

  fprintf(file, "network\n");

  for(i=0; i<conf->num_ifs; i++) {
    fprintf(file, "\tinterface %s%d\n", IFNAMEBASE, i);
    fprintf(file, "\t\tdhcp %s\n", conf->dhcp[i]);
    fprintf(file, "\t\tip %s\n", conf->ip[i]);
    fprintf(file, "\t\tnetmask %s\n", conf->nmask[i]);
    fprintf(file, "\t\tbroadcast %s\n", conf->bcast[i]);
    fprintf(file, "\t\texit\n");
  }

  fprintf(file, "\tdefault %s\n", conf->gw);

  for(i=0; i<ROUTE_NUM; i++) {
    fprintf(file, "\troute %d\n", i);
    fprintf(file, "\t\tset %s\n", conf->route[i]);
    fprintf(file, "\t\texit\n");
  }

  fprintf(file, "\tresolver\n");
  fprintf(file, "\t\tprimary %s\n", conf->ns1);
  fprintf(file, "\t\tsecondary %s\n", conf->ns2);
  fprintf(file, "\t\tsearch %s\n", conf->ns_search);
  fprintf(file, "\t\texit\n");
  fprintf(file, "\texit\n");

  fprintf(file, "role %s\n", conf->role);


  return;

}


int main(int argc, char * argv[])
{
  char *line, *s;
  int ret;
  int setup = 0;
  progname = argv[0];

  initialize_readline();	/* Bind our completer. */
  
  if((argc == 2) && checkarg(argv[1], "setup") ) {

    setup = 1;
    show_prompt = 0;

    if( !(rl_instream = fopen(CONFIG_PATH, "r")) ) /* Set the input stream for readline */
    {
	printf("Failed to open config file %s\n", strerror(errno));
	exit(1);
    }
    
  } else if ((argc == 2) && checkarg(argv[1], "clean") ) {    
    
    setup = 1;
    show_prompt = 1;

  } else if ((argc == 2) && checkarg(argv[1], "silent") ) {    
    
    setup = 0;
    show_prompt = 0;

  } else if (argc > 1) {
   
    usage(argv[0]);

  }


  if((ret = init_config(setup))) {
    printf("Internal error: %s\n", strerror(ret));
  }

  set_prompt(NULL);

  /* There is nothing we can do if this fails, so we don't check */
  signal(SIGINT, SIG_IGN);

  /* Loop reading and executing lines until the user quits. */
  for ( ; done == 0; )
    {
      line = readline((show_prompt ?  prompt : ""));

      if (!line)
        break;

      /* Remove leading and trailing whitespace from the line.
         Then, if there is anything left, add it to the history list
         and execute it. */
      s = stripwhite (line);

      if (*s)
        {
          add_history(s);
          execute_line(s);
        }

      free (line);
    }
  
  close(conf_fd);
  exit (0);
}

/* Execute a command line. */
int execute_line (char *line)
{
  register int i;
  COMMAND *command;
  char *word;

  /* Isolate the command word. */
  i = 0;
  while (line[i] && whitespace (line[i]))
    i++;
  word = line + i;

  while (line[i] && !whitespace (line[i]))
    i++;

  if (line[i])
    line[i++] = '\0';

  if(word[0] == '#') {
    return 0;
  }

  command = find_command (word);

  if (!command)
    {
      fprintf (stderr, "%s: No such command.\n", word);
      return (-1);
    }

  /* Get argument to command, if any. */
  while (whitespace (line[i]))
    i++;

  word = line + i;

  /* Call the function. */
  return ((*(command->func)) (word));
}

/* Look up NAME as the name of a command, and return a pointer to that
   command.  Return a NULL pointer if NAME isn't a command name. */

COMMAND * find_command (char *name)
{
  register int i;

  for (i = 0; commands[i].name; i++)
    if ( checkarg(name, commands[i].name) )
      return (&commands[i]);

  return ((COMMAND *)NULL);
}

/* Strip whitespace from the start and end of STRING.  Return a pointer
   into STRING. */
char * stripwhite (char *string)
{
  register char *s, *t;

  for (s = string; whitespace (*s); s++)
    ;
    
  if (*s == 0)
    return (s);

  t = s + strlen (s) - 1;
  while (t > s && whitespace (*t))
    t--;
  *++t = '\0';

  return s;
}

/* Commit a file atomicly */

int commit_file(char * tmp_file, char *file) {

  if((rename(tmp_file, file)) != 0) {
    unlink(tmp_file);
    return errno;
  }

  return 0;

}

/* **************************************************************** */
/*                                                                  */
/*                  Interface to Readline Completion                */
/*                                                                  */
/* **************************************************************** */


/* Tell the GNU Readline library how to complete.  We want to try to complete
   on command names if this is the first word in the line, or on parameters 
   if not. */

void initialize_readline(void)
{
  rl_command_func_t *func; 

  /* Allow conditional parsing of the ~/.inputrc file. */
  rl_readline_name = APP_NAME;

  /* Tell the completer that we want a crack first. */
  rl_attempted_completion_function = cfgsh_completion;

  /* Make ? function as context sensative help, same as TAB*/
  func = rl_named_function("menu_complete");
  rl_bind_key('?', rl_complete);


}

char ** path_completion_matches(const char * text, char * path, int start)
{

  /* The sanity check from from hell... */
    if((word_num(start, rl_line_buffer) == 1) &&
       (path != NULL) && 
       (strstr(text, "..") == NULL) &&
       (index(text, '/') != text) &&
       (index(text, '.') != text) &&
       (chdir(path) == 0)) {

      rl_attempted_completion_over = 0;
    }
    return (char **)NULL;
}

/* Generator function for interface completion.  STATE lets us know whether
   to start from scratch; without any state (i.e. STATE == 0), then we
   start at the top of the list. */

char * interface_generator(const char *text, int state)
{
  static int list_index;

  /* If this is a new word to complete, initialize now.  This includes
     saving the length of TEXT for efficiency, and initializing the index
     variable to 0. */

  if (!state) {
    list_index = 0;
  }

  if(list_index < conf->num_ifs){

    char * if_name = xmalloc(IFNAMESIZ);
    
    if(!if_name) goto out;
    
    snprintf(if_name, IFNAMESIZ, "%s%d", IFNAMEBASE, list_index++);

    if( checkarg(if_name, text) ) {
      return if_name;
    }
    
    free(if_name);
  }
  
  out:

  /* If no names matched, then return NULL. */
  return ((char *)NULL);
}

char * opt_generator(char ** gen_options, const char *text, int state)
{
  static int list_index;
  char * name;

  /* If this is a new word to complete, initialize now.  This includes
     saving the length of TEXT for efficiency, and initializing the index
     variable to 0. */

  if (!state) {
    list_index = 0;
  }


  /* Return the next name which partially matches from the command list. */
  while ((name = gen_options[list_index]))
    {
      list_index++;

      if ( checkarg(name, text) )
        return (dupstr(name));
    }

  /* If no names matched, then return NULL. */
  return ((char *)NULL);

}

char * show_generator(const char *text, int state)
{
  return opt_generator(show_options, text, state);
}

char * dhcp_generator(const char *text, int state)
{
  return opt_generator(dhcp_options, text, state);
}

char ** interface_completion_matches(const char * text, char * dummy, int start)

{
  if(word_num(start, rl_line_buffer) == 1)
    return rl_completion_matches(text, interface_generator);

  return NULL;
  
}

char ** route_completion_matches(const char * text, char * dummy, int start)

{
  if(word_num(start, rl_line_buffer) == 3)
    return rl_completion_matches(text, interface_generator);

  return NULL;
  
}


char ** show_completion_matches(const char * text, char * dummy, int start)

{
  if(word_num(start, rl_line_buffer) == 1)
    return rl_completion_matches(text, show_generator);

  return NULL;
  
}


char ** dhcp_completion_matches(const char * text, char * dummy, int start)

{
  if(word_num(start, rl_line_buffer) == 1)
    return rl_completion_matches(text, dhcp_generator);

  return NULL;
  
}

/* Attempt to complete on the contents of TEXT.  START and END bound the
   region of rl_line_buffer that contains the word to complete.  TEXT is
   the word to complete.  We can use the entire contents of rl_line_buffer
   in case we want to do some simple parsing.  Return the array of matches,
   or NULL if there aren't any. */
char ** cfgsh_completion (const char *text, int start, int end)
{
  char **matches = (char **)NULL;

  rl_attempted_completion_over = 1;

  if(!show_prompt)
	goto the_end;

  /* If this word is at the start of the line, then it is a command
     to complete.  Otherwise it is the name of a file in the current
     directory. */
  if (start == 0)
    matches = rl_completion_matches(text, command_generator);

  else {
    
    int size, i;
    char * cmd, * cmd_end  = strpbrk(rl_line_buffer, rl_basic_word_break_characters);

    if(!cmd_end)
      goto the_end;

    size = cmd_end - rl_line_buffer;
    cmd = xmalloc(size+1);
    strncpy(cmd, rl_line_buffer, size);
    cmd[size] = 0;

    for (i = 0; commands[i].name; i++)
      {
	if (!*cmd || checkarg(cmd, commands[i].name) )
	  {
	    complete_func_t * func = commands[i].complete_func;

	    if(func)
	      matches = func(text, commands[i].complete_param, start);
	  }
      }

    if(!matches) {
      printf ("\n");
      com_help(cmd);
    }
  
    free(cmd);
    rl_reset_line_state();
  }

 the_end:  
  return (matches);
}

/* Generator function for command completion.  STATE lets us know whether
   to start from scratch; without any state (i.e. STATE == 0), then we
   start at the top of the list. */

char * command_generator(const char *text, int state)
{
  static int list_index;
  char *name;

  /* If this is a new word to complete, initialize now.  This includes
     saving the length of TEXT for efficiency, and initializing the index
     variable to 0. */

  if (!state)
    {
      list_index = 0;
    }

  /* Return the next name which partially matches from the command list. */
  while ((name = commands[list_index].name))
    {
      list_index++;

      if ( checkarg(name, text) )
        return (dupstr(name));
    }

  /* If no names matched, then return NULL. */
  return ((char *)NULL);
}

int getifr(char * arg, char * ifrname, unsigned int * ifr)
{

  arg = stripwhite(arg);

  if(sscanf(arg, IFNAMEBASE "%d", ifr) != 1) {
   return EINVAL;
  }

  if(*ifr > conf->num_ifs) {
    return EINVAL;
  }

  snprintf(ifrname, IFNAMESIZ, "%s%d", IFNAMEBASE, *ifr);

  return 0;

}


/* **************************************************************** */
/*                                                                  */
/*                       Commands                                   */
/*                                                                  */
/* **************************************************************** */

int com_ip (char *arg)
{
  int ret;
  char ip[IPQUADSIZ];

  arg = stripwhite(arg);
  
  if (*arg) {

    if( checkarg(arg, "none") ) {
      strncpy(conf->ip[current_ifr], "none", IPQUADSIZ);

    } else if((ret = set_if_address(ifrname, arg, SET_ADDRESS, conf->ip[current_ifr]))) {
      printf("Error setting static IP address of interface %s to %s: %s\n", ifrname, arg, strerror(ret));
      goto out;

    }

    /* Setting the IP clears the netmask and broadcast info so we need to
       reset them here. Errors are disregarded because the configuration
       doesn't contain anything of value in all events so this may fail for
       a good reason. It's crude, but it works. */

    set_if_address(ifrname, conf->nmask[current_ifr], SET_NETMASK, ip);
    
    /* broadcast may be automatic, in which case we need to run
       the auto code, otherwise, just do same as with netmask */

    if( checkarg(conf->bcast[current_ifr], "auto") ) {
      auto_broadcast(current_ifr);
    } else {
      set_if_address(ifrname, conf->bcast[current_ifr], SET_BROADCAST, ip);
    }

    printf ("Static IP address of interface %s set to %s\n", ifrname, conf->ip[current_ifr]);

  } else {

    printf ("Current configured static IP address for interface %s is %s\n", ifrname, conf->ip[current_ifr]);
    
    if(get_if_address(ifrname, ip, GET_ADDRESS) == 0) {
      printf ("Current actual IP address is %s\n", ip);
    }
  }

 out:
  return 0;
}

int com_netmask (char *arg)
{

  int ret;


  arg = stripwhite(arg);
  
  if (*arg) {
    
    if( checkarg(arg, "none") ) {
      strncpy(conf->nmask[current_ifr], "none", IPQUADSIZ);

    } else if((ret = set_if_address(ifrname, arg, SET_NETMASK, conf->nmask[current_ifr]))) {
      printf("Error setting static netmask address for interface %s to %s: %s\n", ifrname, arg, strerror(ret));
      goto out;
    }

    /* if broadcast is set automatic, adapt to new netmask */
    if( checkarg(conf->bcast[current_ifr], "auto") ) {
      auto_broadcast(current_ifr);
    }

    printf ("Static netmask address for interface %s set to %s\n", ifrname, conf->nmask[current_ifr] );
    
  } else {
    
    char nmask[IPQUADSIZ];

    printf ("Current configured static netmask address for interface %s is %s\n", ifrname, conf->nmask[current_ifr]);

    if(get_if_address(ifrname, nmask, GET_NETMASK) == 0) {
      printf ("Current actual netmask address for interface %s is %s\n", ifrname, nmask);
    }
    
  }
  
 out:
  return 0;

}


int com_broadcast (char *arg)
{
  int ret;
  
  arg = stripwhite(arg);
  
  // ???  auto_broadcast(current_ifr);

  if (*arg) {
    
    if( checkarg(arg, "none") ) {

      strncpy(conf->bcast[current_ifr], "none", IPQUADSIZ);

    } else if( checkarg(arg, "auto") ) {

      strncpy(conf->bcast[current_ifr], "auto", IPQUADSIZ);
      auto_broadcast(current_ifr);
      
    } else if((ret = set_if_address(ifrname, arg, SET_BROADCAST, conf->bcast[current_ifr]))) {
      
      printf("Error setting static broadcast address for interface %s to %s: %s\n", ifrname, arg, strerror(ret));
      goto out;
	
    }

    printf ("Static broadcast address for interface %s set to %s\n", ifrname, conf->bcast[current_ifr]);

  } else {
    
    char bcast[IPQUADSIZ];

    printf ("Current configured static broadcast address for interface %s is %s\n", ifrname, conf->bcast[current_ifr]);

    if(get_if_address(ifrname, bcast, GET_BROADCAST) == 0) {
      printf ("Current actual broadcast address for interface %s is %s\n", ifrname, bcast);
    }


  }
  
 out:
  return 0;

}


int com_show(char * arg)
{
  
  arg = stripwhite(arg);
  unsigned int i;
  
  if (*arg) {
    
    if( checkarg(arg, SHOW_OPT_INTERFACES) ) {
      
      for(i=0; i<conf->num_ifs; i++) {
	current_ifr=i;
	sprintf(ifrname, "%s%d", IFNAMEBASE, i);
	com_ip("");
	com_netmask("");
	com_broadcast("");
	com_dhcp("");
      }
      
      return 0;
    }
       
    if( checkarg(arg, SHOW_OPT_ROUTES) ) {

      for(i=0; i<ROUTE_NUM; i++) {
	current_route=i;
	com_show_route("");
      }
      
      return 0;
    }


    if( checkarg(arg, SHOW_OPT_RESOLVER) ) {

      com_ns("");
      com_ns2("");
      com_search("");
      
      return 0;
    }
    
    if( checkarg(arg, SHOW_OPT_CONFIG) ) {
	    
      dump_config(stdout);
      
      return 0;
    }

  }

  com_help("show");
  
  return 1;

}

int com_save(char * arg)
{

  int ret=0;
  FILE * file;

  /* See remark about random file names later on... */
  
  if(!(file = fopen(CONFIG_PATH".tmp", "w"))) {
    ret = errno;
    goto out;
  }
  
  dump_config(file);

  fclose(file);

  ret = commit_file(CONFIG_PATH".tmp", CONFIG_PATH);

 out:

  if(ret) {
    printf("Save failed! - %s\n", strerror(ret));
  } else {
    printf("Configuration saved\n");
  }
  
  return ret;


}


int com_role (char *arg)
{

  arg = stripwhite(arg);
  
  if (*arg) {
    
    char rolepath[PATH_MAX];
    struct stat statbuf;
    
    if(strstr(arg, "..") || (index(arg, '/') == arg)) {
      /* Damn script kiddies... */
      goto failure;
    }
    
    snprintf(rolepath, PATH_MAX, ROLES_PATH"/%s", arg);
    
    if(stat(rolepath, &statbuf) < 0) {
      goto failure;
    }
    
    if(!S_ISREG(statbuf.st_mode)) {
      goto failure;
    }
    
    unlink(ROLE_PATH);
    
    if(symlink(rolepath, ROLE_PATH) == 0 ) {
      printf("Role set to %s.\n", arg);
      strncpy(conf->role, arg, PATH_MAX);
    } else {
      printf("Role setup failure!\n");
    }
    
  } else {
    printf ("Role is %s\n", conf->role);
  }
  
  return 0;
  
 failure:  
  printf("%s is not a valid role. \n", arg);
  return 0;


}


int com_ns (char *arg)
{
  int ret;
  
  arg = stripwhite(arg);
  
  if (*arg) {
    
    struct in_addr inp;
    char new_ns[IPQUADSIZ];
    
    if( checkarg(arg, "none") ) {
      
      strncpy(new_ns, "none", IPQUADSIZ);
      
    } else {
      
      if(inet_aton(arg, &inp) == 0) {
	ret = EINVAL;
	goto error;
      }

      snprintf(new_ns, IPQUADSIZ, "%d.%d.%d.%d", NIPQUAD(inp.s_addr));
    }
    

    if((ret = write_resolver(new_ns, conf->ns2, conf->ns_search)) != 0) {
      goto error;
    }

    strncpy(conf->ns1, new_ns, IPQUADSIZ);
      
    printf ("Primary name server address set to %s\n", conf->ns1);

  } else {

    printf ("Primary name server address is %s\n", conf->ns1);

  }

  return 0;

 error:
  
  printf("Error setting primary nameserver address to %s: %s\n", arg, strerror(ret));
  return 0;

}

int com_ns2 (char *arg)
{
  int ret;
  
  arg = stripwhite(arg);
  
  if (*arg) {
    
    struct in_addr inp;
    char new_ns[IPQUADSIZ];
    
    if( checkarg(arg, "none") ) {
      
      strncpy(new_ns, "none", IPQUADSIZ);
      
    } else {
      
      if(inet_aton(arg, &inp) == 0) {
	ret = EINVAL;
	goto error;
      }

      snprintf(new_ns, IPQUADSIZ, "%d.%d.%d.%d", NIPQUAD(inp.s_addr));
    }
    

    if((ret = write_resolver(conf->ns1, new_ns, conf->ns_search)) != 0) {
      goto error;
    }

    strncpy(conf->ns2, new_ns, IPQUADSIZ);
      
    printf ("Secondary name server address set to %s\n", conf->ns2);

  } else {

    printf ("Secondary name server address is %s\n", conf->ns2);

  }

  return 0;

 error:
  
  printf("Error setting secondary nameserver address to %s: %s\n", arg, strerror(ret));
  return 0;

}

int com_search (char *arg)
{
  int ret;
  
  arg = stripwhite(arg);
  
  if (*arg) {
    
    if((ret = write_resolver(conf->ns1, conf->ns2, arg)) != 0) {
      goto error;
    }

    strncpy(conf->ns_search, arg, HOST_NAME_MAX);
      
    printf ("Search domain set to %s\n", conf->ns_search);

  } else {

    printf ("Search domain is %s\n", conf->ns_search);

  }

  return 0;

 error:
  
  printf("Error setting search domain to %s: %s\n", arg, strerror(ret));
  return 0;

} 

#define NULLADDR(_X) { _X.sin_port=0; _X.sin_family=AF_INET; _X.sin_addr.s_addr = INADDR_ANY;} while(0)

int com_del_route (char *arg)
{
  struct sockaddr_in target, netmask, gateway;
  char * dev = NULL, * target_s, * netmask_s, *gateway_s = NULL;
  int ret, sock;
  struct rtentry rt;

  NULLADDR(target);
  NULLADDR(netmask);
  NULLADDR(gateway);

  arg = strdup(conf->route[current_route]);

  target_s = strtok(arg, rl_basic_word_break_characters);

  if(!target_s)
    goto noarg;

  if( checkarg(target_s, "none") ) {
    return 0;
  }
  
  if ((ret = resolve(&target, target_s)) != 0) {
    goto error;
  }

  netmask_s = strtok(NULL, rl_basic_word_break_characters);

  if(!netmask_s)
    goto noarg;
  
  if ((ret = resolve(&netmask, netmask_s)) != 0) {
    goto error;
  }


  dev = strtok(NULL, rl_basic_word_break_characters);

  if(!dev)
    goto noarg;

  gateway_s = strtok(NULL, rl_basic_word_break_characters);

  if(!gateway_s)
    goto doit;

  if ((ret = resolve(&gateway, gateway_s)) != 0) {
    goto error;
  }

 doit:

  memset(&rt, 0, sizeof(struct rtentry));

  rt.rt_flags = RTF_UP;
  rt.rt_metric = current_route;
  
  memcpy(&rt.rt_dst, &target, sizeof(struct sockaddr));
  memcpy(&rt.rt_genmask, &netmask, sizeof(struct sockaddr));

  if(gateway_s) {
      rt.rt_flags |= RTF_GATEWAY;
      memcpy(&rt.rt_gateway, &gateway, sizeof(struct sockaddr));
  }

  if(dev)
    rt.rt_dev = dev;

  if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
    ret = errno;
    goto error;
  }

  if((ret = ioctl(sock, SIOCDELRT , &rt)) != 0) {
    ret = errno;
    goto error;
  }
    
  close(sock);  

  strcpy(conf->route[current_route], "none");

  free(arg);
  return 0;

 error:
  printf("Invalid route %s: %s\n",conf->route[current_route] , strerror(ret));
  free(arg);
  com_help("delete");
  return 2;
  
 noarg:
  printf("Required argument missing: %s\n", conf->route[current_route]);  
  free(arg);
  com_help("delete");
  return 1;

}

int com_show_route (char *arg)
{
  printf("Route number %d is: %s\n", current_route, conf->route[current_route]);  
  return 0;
}

int com_set_route (char *arg)
{
  struct sockaddr_in target, netmask, gateway;
  char * dev = NULL, * target_s, * netmask_s, *gateway_s;
  char tmp_route_s[MAX_ROUTE_SIZE];
  int ret, sock;
  struct rtentry rt;

  NULLADDR(target);
  NULLADDR(netmask);
  NULLADDR(gateway);

  target_s = strtok(arg, rl_basic_word_break_characters);

  if(!target_s)
    goto noarg;

  if( checkarg(target_s, "none") ) {
    return com_del_route("");
  }
  
  if ((ret = resolve(&target, target_s)) != 0) {
    goto error;
  }

  netmask_s = strtok(NULL, rl_basic_word_break_characters);

  if(!netmask_s)
    goto noarg;
  
  if ((ret = resolve(&netmask, netmask_s)) != 0) {
    goto error;
  }

  dev = strtok(NULL, rl_basic_word_break_characters);

  if(!dev)
    goto noarg;

  gateway_s = strtok(NULL, rl_basic_word_break_characters);
  
  if(!gateway_s)
    goto doit;

  if ((ret = resolve(&gateway, gateway_s)) != 0) {
    goto error;
  }

 doit:

  memset(&rt, 0, sizeof(struct rtentry));

  rt.rt_flags = RTF_UP;
  rt.rt_metric = current_route;
  
  memcpy(&rt.rt_dst, &target, sizeof(struct sockaddr));
  memcpy(&rt.rt_genmask, &netmask, sizeof(struct sockaddr));

  if(gateway_s) {
      rt.rt_flags |= RTF_GATEWAY;
      memcpy(&rt.rt_gateway, &gateway, sizeof(struct sockaddr));
  }
  
  rt.rt_dev = dev;

  if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
    ret = errno;
    goto error;
  }

  if((ret = ioctl(sock, SIOCADDRT , &rt)) != 0) {
    ret = errno;
    goto error;
  }
    
  close(sock);  

  snprintf(tmp_route_s, MAX_ROUTE_SIZE, "%s %s ", target_s, netmask_s);

  if(dev)
    strncat(tmp_route_s, dev, MAX_ROUTE_SIZE);

  if(gateway_s) {
    strncat(tmp_route_s, " ", MAX_ROUTE_SIZE);
    strncat(tmp_route_s, gateway_s, MAX_ROUTE_SIZE);
  }

  strcpy(conf->route[current_route], tmp_route_s);

  return 0;

 error:
  printf("Invalid route: %s\n", strerror(ret));
  com_help("set");
  return 2;
  
 noarg:
  printf("Required argument missing\n");
  com_help("set");
  return 1;

}

int com_gw (char *arg)
{
  int sock, ret, none;
  struct rtentry rt;
  struct sockaddr_in sockaddr, deladdr;
  

  arg = stripwhite(arg);
  
  if (!*arg) {

    printf ("Static broadcast address is %s\n", conf->gw);
    return 0;
    
  }

  none = ( checkarg(arg, "none") );

  deladdr.sin_family = sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = 0;

  if ((!none) && ((ret = resolve(&sockaddr, arg)) != 0) ) {
    goto error;
  }

  if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
    ret = errno;
    goto error;
  }

  memset(&rt, 0, sizeof(struct rtentry));
  rt.rt_flags = RTF_UP | RTF_GATEWAY;
  rt.rt_metric = current_route;
  
  deladdr.sin_addr.s_addr = INADDR_ANY;
  memcpy(&rt.rt_dst, &deladdr, sizeof(struct sockaddr));
  
  deladdr.sin_addr.s_addr = INADDR_ANY;
  memcpy(&rt.rt_genmask, &deladdr, sizeof(struct sockaddr));

  deladdr.sin_addr.s_addr = INADDR_ANY;
  memcpy(&rt.rt_gateway, &deladdr, sizeof(struct sockaddr));
  
  /* this can fail if we've just came up */
  ioctl(sock, SIOCDELRT , &rt);
  
  if(none) {
    strncpy(conf->gw, "none", IPQUADSIZ);
    goto ok;
  } 
  
  memcpy(&rt.rt_gateway, &sockaddr, sizeof(struct sockaddr));
  
  if((ret = ioctl(sock, SIOCADDRT , &rt)) != 0) {
    ret = errno;
    goto error;
  }
    
  close(sock);
  
  snprintf(conf->gw, IPQUADSIZ, "%d.%d.%d.%d", NIPQUAD(sockaddr.sin_addr));

 ok:
  printf ("Static gateway address set to %s\n", conf->gw);
  return 0;
  
 error:
  printf("Error setting static gateway address to %s: %s\n", arg, strerror(ret));
  return ret;
  
}

int com_dhcp (char *arg)
{

  arg = stripwhite(arg);

  if (!*arg) {
    printf ("DHCP is %s for interface %s\n", conf->dhcp[current_ifr], ifrname);
    goto out;
  }

  if( checkarg(arg, DHCP_OPT_ON) ) {

    char *cmd[4] = { DHCPCD_START_PATH , ifrname, conf->hostname  , NULL};

    if(conf->dhcp_is_on[current_ifr]) {
      printf("DHCP is already on for interface %s. Turn it off first to make changes\n", ifrname);
      return 1; 
    }
      
    strncpy(conf->dhcp[current_ifr], DHCP_OPT_ON, sizeof(DHCP_OPT_ON));

    if(safesystem(DHCPCD_START_PATH, cmd) != 0) {
      printf("Failed getting DHCP response on interface %s. Will use static information.\n", ifrname);

    } else {

      conf->dhcp_is_on[current_ifr] = 1;
      printf("DHCP is on for interface %s\n", ifrname);
    }

    goto out;

  }
  

  if( checkarg(arg, DHCP_OPT_IPONLY) ) {

    char *cmd[4] = { DHCPCD_IPONLY_PATH , ifrname, conf->hostname, NULL};

    strncpy(conf->dhcp[current_ifr], DHCP_OPT_IPONLY, sizeof(DHCP_OPT_IPONLY));

    if(conf->dhcp_is_on[current_ifr]) {
      printf("DHCP is already on for interface %s. Turn it off first to make changes\n", ifrname);
      return 1; 
    }
                                                                                                            
    if(safesystem(DHCPCD_START_PATH, cmd) != 0) {
      printf("Failed getting DHCP response in iponly mode on interface %d. Will use static information.\n", current_ifr);

    } else {
      conf->dhcp_is_on[current_ifr] = 1;
      printf("DHCP is on in iponly mode for interface %d\n", current_ifr);
    }

    goto out;
  }

  if( checkarg(arg, DHCP_OPT_OFF) ) {

    char *cmd[3] = { DHCPCD_STOP_PATH, ifrname, NULL};
      
    strncpy(conf->dhcp[current_ifr], DHCP_OPT_OFF, sizeof(DHCP_OPT_OFF));
    safesystem(DHCPCD_STOP_PATH, cmd);
    conf->dhcp_is_on[current_ifr] = 0;
    printf("DHCP is off for interface %d\n", current_ifr);

  } else 
    printf("Unknown dhcp command %s\n", arg);
 
out: 
return 0;
}

int com_tz (char * arg)
{

  arg = stripwhite(arg);
  
  if (*arg) {
    
    char tzpath[PATH_MAX];
    struct stat statbuf;

    if(!strcmp(arg, "none"))
	goto ok;
    
    if(strstr(arg, "..") || (index(arg, '/') == arg)) {
      /* Damn script kiddies... */
      goto failure;
    }
    
    snprintf(tzpath, PATH_MAX, ZONES_PATH"/%s", arg);
    
    if(stat(tzpath, &statbuf) < 0) {
      goto failure;
    }
    
    if(!S_ISREG(statbuf.st_mode)) {
      goto failure;
    }
    
    unlink(TZ_PATH);
    
    if(symlink(tzpath, TZ_PATH) == 0 ) {
      printf("Time zone set to %s.\n", arg);
      strncpy(conf->tz, arg, PATH_MAX);
    } else {
      printf("Time zone setup failure!");
    }
    
  } else {
    printf ("Timezone is %s\n", conf->tz);
  }
 
 ok: 
  return 0;
  
 failure:  
  printf("%s is not a valid time zone. \n", arg);
  return 0;
  
}

/* Print out help for ARG, or for all of the commands if ARG is
   not present. */

int com_help (char *arg)
{
  register int i;
  int printed = 0;
  for (i = 0; commands[i].name; i++)
    {
      if (!*arg || checkarg(arg, commands[i].name) )
        {
          printf ("%10s  %s.\n", commands[i].name, commands[i].doc);
          printed++;
        }
    }

  if (!printed)
    {
      printf ("No commands match `%s'.  Possibilties are:\n", arg);

      for (i = 0; commands[i].name; i++)
        {
          /* Print in six columns. */
          if (printed == 6)
            {
              printed = 0;
              printf ("\n");
            }

          printf ("%s\t", commands[i].name);
          printed++;
        }

      if (printed)
        printf ("\n");
    }
  return (0);
}

/* Ping hostname or IP address PING_COUNT times. */
int com_ping (char *arg)
{

  char * cmd[5] = { PING_PATH, PING_COUNT_PARAM, PING_COUNT, arg, NULL };
  int ret;

  if ((ret = safesystem (PING_PATH, cmd)) == 0)
    {
      printf("ping %s - %s\n", arg, strerror(ret));
      return 1;
    }

  return (0);
}

/* Power off the system */
int com_halt (char *arg)
{

  kill(1, SIGUSR2);

  return (0);
}

/* Reboot the system */
int com_reboot (char *arg)
{

  kill(1, SIGTERM);
  
  return (0);

}

/* The user wishes to quit using this program.  Just set DONE non-zero. */
int com_quit (char *arg)
{

  done = 1;
  return (0);
}

/* switch to network mode */
int com_net (char *arg)
{
  commands = network_commands;
  set_prompt("(network)");
  return (0);
}

/* switch to nameservers mode */
int com_nameservers (char *arg)
{
  commands = nameservers_commands;
  set_prompt("(network resolver)");
  return (0);
}

/* The user wishes to enter interface settings mode */
int com_int (char *arg)
{

  char tmp[PROMPT_SIZE];
                                                                                                                             
  arg = stripwhite(arg);
                                                                                                                             
  if (!*arg) {
                                                                                                                             
    printf ("Please supply an interface name. Press TAB to get a list of available ones.\n");
    return 1;
  }
                                                                                                                             
  if(getifr(arg, ifrname, &current_ifr)) {
    printf("No such interface %s\n.", arg);
    return 1;
  }
                                                                                                                             
  commands = interface_commands;
  snprintf(tmp, PROMPT_SIZE, "(network interface %s)", ifrname);
  set_prompt(tmp);

  return (0);
}

/* Enter route mode */
int com_route (char *arg)
{

  char tmp[PROMPT_SIZE];

  arg = stripwhite(arg);
  
  if (!*arg) {

    printf ("Please supply a route proiority. Press TAB to get a list of available ones.\n");
    return 1;
  }

  current_route=atoi(arg);

  if(current_route > ROUTE_NUM) {
    printf("Only %d routes allowed!\n", ROUTE_NUM);
    return 1;
  }

  commands = route_commands;
  snprintf(tmp, PROMPT_SIZE, "(network route %s)", arg);
  set_prompt(tmp);

  return (0);
}

/* Return to root mode */
int com_root (char *arg)
{

  commands = root_commands;
  set_prompt(NULL);

  return (0);
}

/* Set hostname */
int com_hostname (char *arg)
{

  int size;
  arg = stripwhite(arg);
  
  if (!*arg) {

    printf ("Host name is %s\n", conf->hostname);
    return 0;
    
  }

  size = strlen(arg) + 1;

  if(size > HOST_NAME_MAX)
    {    
      printf("Setting of hostname to %s failed because it's too long.\n", arg);
      return 1;
    }

  if(sethostname(arg, size))
  {
    printf("Setting of hostname to %s failed because %s\n", arg, strerror(errno));
    return 1;
  }
  
  snprintf(conf->hostname, HOST_NAME_MAX - 1, arg); 

  return (0);
}

