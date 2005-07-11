/* Copyright (C) 2003 Gilad Ben-Yossef <gilad@benyossef.com>
   Copyright (C) 2004 Codefidence Ltd. http://www.codefidence.com

   This file is part of cfgsh -- A tiny configuration 'shell' 
   for embedded systems. It gives an embedded system user a limited
   interface for configuring basic system properties in an easy 
   manner, with context sensative help and history managment.
   
   It is heavily based on the fileman.c example distributed with
   the GNU readline library :-) 

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

#ifndef INCLUDE_CFGSH_H
#define INCLUDE_CFGSH_H

#define IPQUADSIZ (16)
#define IFNAMEBASE "eth"
#define IFNAMESIZ 5
#define MAXIF (3)
#define NUMIF (MAXIF + 1)

#ifndef PATH_MAX
#define PATH_MAX (1024)
#endif

#define MAX_BUF_SIZE (512)

#define TZ_PATH "/etc/localtime"
#define ZONES_PATH "/usr/share/zoneinfo"

#define PING_PATH "/bin/ping"
#define PING_COUNT_PARAM "-c"
#define PING_COUNT "4"

/* Location of system DNS resolver config file */
#define RESOLV_PATH "/etc/resolv.conf"

/* Location of system wide configuration file */
#define CONFIG_PATH "/etc/system.conf"

/* Handle to shared memory segment holding system volatile configuration */
#define STATE_PATH "/cfgsh.state"

/* Location of file to parse for Ethernet interface info */
#define PROC_NET_DEV "/proc/net/dev"

/* Script to run to start DHCP with full options */
#define DHCPCD_START_PATH "/usr/sbin/run-dhcpc"

/* Script to run to start DHCP with only IP options */
#define DHCPCD_STOP_PATH "/usr/sbin/stop-dhcpc"

/* Script to run to stop DHCP */
#define DHCPCD_IPONLY_PATH "/usr/sbin/iponly-dhcpc"


/* Name and max length of DHCP options: on, off and iponly */
#define DHCP_OPT (7)
#define DHCP_OPT_ON "on"
#define DHCP_OPT_IPONLY "iponly"
#define DHCP_OPT_OFF "off"

#define SHOW_OPT_CONFIG "config"
#define SHOW_OPT_INTERFACES "interfaces"
#define SHOW_OPT_RESOLVER "resolver"
#define SHOW_OPT_ROUTES "routes"


/* Path to symlink to current system role */
#define ROLE_PATH "/etc/role"

/* Path to directory with all possible system roles */
#define ROLES_PATH "/etc/roles/"

#define HOST_NAME_MAX (255)
#define APP_NAME "cfgsh"

/* This is the system prompt */
#define PROMPT_SIZE (256)
#define PROMPT ">"

#define MAX_ROUTE_SIZE (255)
#define ROUTE_NUM (3)

/********************************************************
 *
 *      End of user servicable part
 *
 *******************************************************/

/*
 *      Display an IP address in readable format.
 */

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

typedef char ** (complete_func_t)(const char *, char *, int);

/* Command function forwards */
int com_ip PARAMS((char *));
int com_netmask PARAMS((char *));
int com_dhcp PARAMS((char *));
int com_broadcast PARAMS((char *));
int com_gw PARAMS((char *));
int com_ns PARAMS((char *));
int com_ns2 PARAMS((char *));
int com_search PARAMS((char *));
int com_nameservers PARAMS((char *));
int com_role PARAMS((char *));
int com_help PARAMS((char *));
int com_quit PARAMS((char *));
int com_save PARAMS((char *));
int com_show PARAMS((char *));
int com_ping PARAMS((char *));
int com_tz PARAMS((char *));
int com_halt PARAMS((char *));
int com_reboot PARAMS((char *));
int com_net PARAMS((char *));
int com_int PARAMS((char *));
int com_root PARAMS((char *));
int com_hostname PARAMS((char *));
int com_route PARAMS((char *));
int com_set_route PARAMS((char *));
int com_del_route PARAMS((char *));
int com_show_route PARAMS((char *));

/* Completion function forwads */

char ** path_completion_matches(const char *, char *, int);
char ** interface_completion_matches(const char *, char *, int);
char ** show_completion_matches(const char * text, char * dummy, int start);
char ** dhcp_completion_matches(const char * text, char * dummy, int start);
char ** route_completion_matches(const char * text, char * dummy, int start);

/* Utility function forwards */

int find_ifs(void);
char *command_generator PARAMS((const char *, int));
int path_clean PARAMS((char **));
char **cfgsh_completion PARAMS((const char *, int, int));
void initialize_readline(void);
int execute_line (char *line);
int commit_file(char * tmp_file, char *file);

/* A structure which contains information on the commands this program
   can understand. */

typedef struct {
  char *name;			     /* User printable name of the function. */
  rl_icpfunc_t *func;		     /* Function to call to do the job. */
  char *doc;			     /* Documentation for this function.  */
  complete_func_t *complete_func;    /* Function to call for line completition, if any */
  char * complete_param;             /* Parameter to pass to complete_func, if any */
} COMMAND;

typedef struct {
  char ip[NUMIF][IPQUADSIZ];
  char nmask[NUMIF][IPQUADSIZ];
  char bcast[NUMIF][IPQUADSIZ];
  char gw[IPQUADSIZ];
  char ns_search[HOST_NAME_MAX];
  char ns1[IPQUADSIZ];
  char ns2[IPQUADSIZ];
  char role[PATH_MAX];
  char tz[PATH_MAX];
  char dhcp[NUMIF][DHCP_OPT];
  char dhcp_is_on[NUMIF];
  char hostname[HOST_NAME_MAX];
  char route  [ROUTE_NUM][MAX_ROUTE_SIZE];
  char num_ifs;
} CONF;


/* External functions */
extern char *xmalloc ();
  
/* Forward declarations. */
char *stripwhite ();
COMMAND *find_command ();
char * complete_help(char * arg);

/* Enumarators for the address operations that hides
   the IOCTL types */

typedef enum addr_get_ops_enum { 
  GET_NETMASK = SIOCGIFNETMASK,
  GET_BROADCAST = SIOCGIFBRDADDR,
  GET_ADDRESS = SIOCGIFADDR 
} ADDR_GET_OPS;

typedef enum addr_set_ops_enum { 
  SET_NETMASK = SIOCSIFNETMASK,
  SET_BROADCAST = SIOCSIFBRDADDR,
  SET_ADDRESS = SIOCSIFADDR 
} ADDR_SET_OPS;
		

#endif /* INCLUDE_CFGSH_H */
