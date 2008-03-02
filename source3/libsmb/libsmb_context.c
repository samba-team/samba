/* 
   Unix SMB/Netbios implementation.
   SMB client library implementation
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Richard Sharpe 2000, 2002
   Copyright (C) John Terpstra 2000
   Copyright (C) Tom Jansen (Ninja ISD) 2002 
   Copyright (C) Derrell Lipman 2003-2008
   Copyright (C) Jeremy Allison 2007, 2008
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "libsmbclient.h"
#include "libsmb_internal.h"


/*
 * Is the logging working / configfile read ? 
 */
static int SMBC_initialized = 0;



/*
 * Get a new empty handle to fill in with your own info
 */
SMBCCTX *
smbc_new_context(void)
{
        SMBCCTX *context;
        
        /*
         * All newly added context fields should be placed in
         * SMBC_internal_data, not directly in SMBCCTX.
         */
#undef OLD
#define OLD(field)      context->field
#undef NEW
#define NEW(field)      context->internal->field
        
        context = SMB_MALLOC_P(SMBCCTX);
        if (!context) {
                errno = ENOMEM;
                return NULL;
        }
        
        ZERO_STRUCTP(context);
        
        context->internal = SMB_MALLOC_P(struct SMBC_internal_data);
        if (!context->internal) {
                SAFE_FREE(context);
                errno = ENOMEM;
                return NULL;
        }
        
        /* Initialize the context and establish reasonable defaults */
        ZERO_STRUCTP(context->internal);
        
        OLD(config.debug)              = 0;
        OLD(config.timeout)            = 20000; /* 20 seconds */
        
        NEW(full_time_names)           = False;
        NEW(share_mode)                = SMBC_SHAREMODE_DENY_NONE;
        NEW(smb_encryption_level)      = 0;
        OLD(options.browse_max_lmb_count)      = 3;    /* # LMBs to query */
        OLD(options.urlencode_readdir_entries) = False;
        OLD(options.one_share_per_server)      = False;
        
        OLD(server.get_auth_data_fn)        = SMBC_get_auth_data;
        OLD(server.check_server_fn)         = SMBC_check_server;
        OLD(server.remove_unused_server_fn) = SMBC_remove_unused_server;
        
        OLD(cache.server_cache_data)        = NULL;
        OLD(cache.add_cached_server_fn)     = SMBC_add_cached_server;
        OLD(cache.get_cached_server_fn)     = SMBC_get_cached_server;
        OLD(cache.remove_cached_server_fn)  = SMBC_remove_cached_server;
        OLD(cache.purge_cached_servers_fn)  = SMBC_purge_cached_servers;
        
        OLD(posix_emu.open_fn)               = SMBC_open_ctx;
        OLD(posix_emu.creat_fn)              = SMBC_creat_ctx;
        OLD(posix_emu.read_fn)               = SMBC_read_ctx;
        OLD(posix_emu.write_fn)              = SMBC_write_ctx;
        OLD(posix_emu.close_fn)              = SMBC_close_ctx;
        OLD(posix_emu.unlink_fn)             = SMBC_unlink_ctx;
        OLD(posix_emu.rename_fn)             = SMBC_rename_ctx;
        OLD(posix_emu.lseek_fn)              = SMBC_lseek_ctx;
        NEW(posix_emu.ftruncate_fn)          = SMBC_ftruncate_ctx;
        OLD(posix_emu.stat_fn)               = SMBC_stat_ctx;
        OLD(posix_emu.fstat_fn)              = SMBC_fstat_ctx;
        OLD(posix_emu.opendir_fn)            = SMBC_opendir_ctx;
        OLD(posix_emu.closedir_fn)           = SMBC_closedir_ctx;
        OLD(posix_emu.readdir_fn)            = SMBC_readdir_ctx;
        OLD(posix_emu.getdents_fn)           = SMBC_getdents_ctx;
        OLD(posix_emu.mkdir_fn)              = SMBC_mkdir_ctx;
        OLD(posix_emu.rmdir_fn)              = SMBC_rmdir_ctx;
        OLD(posix_emu.telldir_fn)            = SMBC_telldir_ctx;
        OLD(posix_emu.lseekdir_fn)           = SMBC_lseekdir_ctx;
        OLD(posix_emu.fstatdir_fn)           = SMBC_fstatdir_ctx;
        OLD(posix_emu.chmod_fn)              = SMBC_chmod_ctx;
        OLD(posix_emu.utimes_fn)             = SMBC_utimes_ctx;
        OLD(posix_emu.setxattr_fn)           = SMBC_setxattr_ctx;
        OLD(posix_emu.getxattr_fn)           = SMBC_getxattr_ctx;
        OLD(posix_emu.removexattr_fn)        = SMBC_removexattr_ctx;
        OLD(posix_emu.listxattr_fn)          = SMBC_listxattr_ctx;
        
        OLD(printing.open_print_job_fn)      = SMBC_open_print_job_ctx;
        OLD(printing.print_file_fn)          = SMBC_print_file_ctx;
        OLD(printing.list_print_jobs_fn)     = SMBC_list_print_jobs_ctx;
        OLD(printing.unlink_print_job_fn)    = SMBC_unlink_print_job_ctx;
        
        return context;
#undef OLD
#undef NEW
}

/*
 * Free a context
 *
 * Returns 0 on success. Otherwise returns 1, the SMBCCTX is _not_ freed
 * and thus you'll be leaking memory if not handled properly.
 *
 */
int
smbc_free_context(SMBCCTX *context,
                  int shutdown_ctx)
{
        if (!context) {
                errno = EBADF;
                return 1;
        }
        
        if (shutdown_ctx) {
                SMBCFILE * f;
                DEBUG(1,("Performing aggressive shutdown.\n"));
                
                f = context->internal->files;
                while (f) {
                        (context->posix_emu.close_fn)(context, f);
                        f = f->next;
                }
                context->internal->files = NULL;
                
                /* First try to remove the servers the nice way. */
                if (context->cache.purge_cached_servers_fn(context)) {
                        SMBCSRV * s;
                        SMBCSRV * next;
                        DEBUG(1, ("Could not purge all servers, "
                                  "Nice way shutdown failed.\n"));
                        s = context->internal->servers;
                        while (s) {
                                DEBUG(1, ("Forced shutdown: %p (fd=%d)\n",
                                          s, s->cli->fd));
                                cli_shutdown(s->cli);
                                (context->cache.remove_cached_server_fn)(context,
                                                                         s);
                                next = s->next;
                                DLIST_REMOVE(context->internal->servers, s);
                                SAFE_FREE(s);
                                s = next;
                        }
                        context->internal->servers = NULL;
                }
        }
        else {
                /* This is the polite way */
                if ((context->cache.purge_cached_servers_fn)(context)) {
                        DEBUG(1, ("Could not purge all servers, "
                                  "free_context failed.\n"));
                        errno = EBUSY;
                        return 1;
                }
                if (context->internal->servers) {
                        DEBUG(1, ("Active servers in context, "
                                  "free_context failed.\n"));
                        errno = EBUSY;
                        return 1;
                }
                if (context->internal->files) {
                        DEBUG(1, ("Active files in context, "
                                  "free_context failed.\n"));
                        errno = EBUSY;
                        return 1;
                }
        }
        
        /* Things we have to clean up */
        SAFE_FREE(context->config.workgroup);
        SAFE_FREE(context->config.netbios_name);
        SAFE_FREE(context->config.user);
        
        DEBUG(3, ("Context %p successfully freed\n", context));
        SAFE_FREE(context);
        return 0;
}


/**
 * Deprecated interface.  Do not use.  Instead, use the various
 * smbc_setOption*() functions or smbc_setFunctionAuthDataWithContext().
 */
void
smbc_option_set(SMBCCTX *context,
                char *option_name,
                ... /* option_value */)
{
        va_list ap;
        union {
                int i;
                bool b;
                smbc_get_auth_data_with_context_fn auth_fn;
                void *v;
                const char *s;
        } option_value;
        
        va_start(ap, option_name);
        
        if (strcmp(option_name, "debug_to_stderr") == 0) {
                option_value.b = (bool) va_arg(ap, int);
                smbc_setOptionDebugToStderr(context, option_value.b);
                
        } else if (strcmp(option_name, "full_time_names") == 0) {
                option_value.b = (bool) va_arg(ap, int);
                smbc_setOptionFullTimeNames(context, option_value.b);
                
        } else if (strcmp(option_name, "open_share_mode") == 0) {
                option_value.i = va_arg(ap, int);
                smbc_setOptionOpenShareMode(context, option_value.i);
                
        } else if (strcmp(option_name, "auth_function") == 0) {
                option_value.auth_fn =
                        va_arg(ap, smbc_get_auth_data_with_context_fn);
                smbc_setFunctionAuthDataWithContext(context, option_value.auth_fn);
                
        } else if (strcmp(option_name, "user_data") == 0) {
                option_value.v = va_arg(ap, void *);
                smbc_setOptionUserData(context, option_value.v);
                
        } else if (strcmp(option_name, "smb_encrypt_level") == 0) {
                option_value.s = va_arg(ap, const char *);
                if (strcmp(option_value.s, "none") == 0) {
                        smbc_setOptionSmbEncryptionLevel(context,
                                                         SMBC_ENCRYPTLEVEL_NONE);
                } else if (strcmp(option_value.s, "request") == 0) {
                        smbc_setOptionSmbEncryptionLevel(context,
                                                         SMBC_ENCRYPTLEVEL_REQUEST);
                } else if (strcmp(option_value.s, "require") == 0) {
                        smbc_setOptionSmbEncryptionLevel(context,
                                                         SMBC_ENCRYPTLEVEL_REQUIRE);
                }
                
        } else if (strcmp(option_name, "browse_max_lmb_count") == 0) {
                option_value.i = va_arg(ap, int);
                smbc_setOptionBrowseMaxLmbCount(context, option_value.i);
                
        } else if (strcmp(option_name, "urlencode_readdir_entries") == 0) {
                option_value.b = (bool) va_arg(ap, int);
                smbc_setOptionUrlEncodeReaddirEntries(context, option_value.b);
                
        } else if (strcmp(option_name, "one_share_per_server") == 0) {
                option_value.b = (bool) va_arg(ap, int);
                smbc_setOptionOneSharePerServer(context, option_value.b);
                
        } else if (strcmp(option_name, "use_kerberos") == 0) {
                option_value.b = (bool) va_arg(ap, int);
                smbc_setOptionUseKerberos(context, option_value.b);
                
        } else if (strcmp(option_name, "fallback_after_kerberos") == 0) {
                option_value.b = (bool) va_arg(ap, int);
                smbc_setOptionFallbackAfterKerberos(context, option_value.b);
                
        } else if (strcmp(option_name, "no_auto_anonymous_login") == 0) {
                option_value.b = (bool) va_arg(ap, int);
                smbc_setOptionNoAutoAnonymousLogin(context, option_value.b);
        }
        
        va_end(ap);
}


/*
 * Deprecated interface.  Do not use.  Instead, use the various
 * smbc_getOption*() functions.
 */
void *
smbc_option_get(SMBCCTX *context,
                char *option_name)
{
        int             bits;
        
        if (strcmp(option_name, "debug_stderr") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) smbc_getOptionDebugToStderr(context);
#else
                return (void *) smbc_getOptionDebugToStderr(context);
#endif
                
        } else if (strcmp(option_name, "full_time_names") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) smbc_getOptionFullTimeNames(context);
#else
                return (void *) smbc_getOptionFullTimeNames(context);
#endif
                
        } else if (strcmp(option_name, "open_share_mode") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) smbc_getOptionOpenShareMode(context);
#else
                return (void *) smbc_getOptionOpenShareMode(context);
#endif
                
        } else if (strcmp(option_name, "auth_function") == 0) {
                return (void *) smbc_getFunctionAuthDataWithContext(context);
                
        } else if (strcmp(option_name, "user_data") == 0) {
                return smbc_getOptionUserData(context);
                
        } else if (strcmp(option_name, "smb_encrypt_level") == 0) {
                switch(smbc_getOptionSmbEncryptionLevel(context))
                {
                case 0:
                        return (void *) "none";
                case 1:
                        return (void *) "request";
                case 2:
                        return (void *) "require";
                }
                
        } else if (strcmp(option_name, "smb_encrypt_on") == 0) {
                SMBCSRV *s;
                unsigned int num_servers = 0;
                
                for (s = context->internal->servers; s; s = s->next) {
                        num_servers++;
                        if (s->cli->trans_enc_state == NULL) {
                                return (void *)false;
                        }
                }
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) (bool) (num_servers > 0);
#else
                return (void *) (bool) (num_servers > 0);
#endif
                
        } else if (strcmp(option_name, "browse_max_lmb_count") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) smbc_getOptionBrowseMaxLmbCount(context);
#else
                return (void *) smbc_getOptionBrowseMaxLmbCount(context);
#endif
                
        } else if (strcmp(option_name, "urlencode_readdir_entries") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *)(intptr_t) smbc_getOptionUrlEncodeReaddirEntries(context);
#else
                return (void *) (bool) smbc_getOptionUrlEncodeReaddirEntries(context);
#endif
                
        } else if (strcmp(option_name, "one_share_per_server") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) smbc_getOptionOneSharePerServer(context);
#else
                return (void *) (bool) smbc_getOptionOneSharePerServer(context);
#endif
                
        } else if (strcmp(option_name, "use_kerberos") == 0) {
                bits = context->flags.bits;
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) smbc_getOptionUseKerberos(context);
#else
                return (void *) (bool) smbc_getOptionUseKerberos(context);
#endif
                
        } else if (strcmp(option_name, "fallback_after_kerberos") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *)(intptr_t) smbc_getOptionFallbackAfterKerberos(context);
#else
                return (void *) (bool) smbc_getOptionFallbackAfterKerberos(context);
#endif
                
        } else if (strcmp(option_name, "no_auto_anonymous_login") == 0) {
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
                return (void *) (intptr_t) smbc_getOptionNoAutoAnonymousLogin(context);
#else
                return (void *) (bool) smbc_getOptionNoAutoAnonymousLogin(context);
#endif
        }
        
        return NULL;
}


/*
 * Initialize the library, etc.
 *
 * We accept a struct containing handle information.
 * valid values for info->debug from 0 to 100,
 * and insist that info->fn must be non-null.
 */
SMBCCTX *
smbc_init_context(SMBCCTX *context)
{
        int pid;
        char *user = NULL;
        char *home = NULL;
        extern bool in_client;
        
        if (!context) {
                errno = EBADF;
                return NULL;
        }
        
        /* Do not initialise the same client twice */
        if (context->internal->initialized) {
                return 0;
        }
        
        if (!context->server.get_auth_data_fn ||
            context->config.debug < 0 ||
            context->config.debug > 100) {
                
                errno = EINVAL;
                return NULL;
                
        }
        
        if (!SMBC_initialized) {
                /*
                 * Do some library-wide intializations the first time we get
                 * called
                 */
                bool conf_loaded = False;
                TALLOC_CTX *frame = talloc_stackframe();
                
                /* Set this to what the user wants */
                DEBUGLEVEL = context->config.debug;
                
                load_case_tables();
                
                setup_logging("libsmbclient", True);
                if (context->internal->debug_stderr) {
                        dbf = x_stderr;
                        x_setbuf(x_stderr, NULL);
                }
                
                /* Here we would open the smb.conf file if needed ... */
                
                in_client = True; /* FIXME, make a param */
                
                home = getenv("HOME");
                if (home) {
                        char *conf = NULL;
                        if (asprintf(&conf, "%s/.smb/smb.conf", home) > 0) {
                                if (lp_load(conf, True, False, False, True)) {
                                        conf_loaded = True;
                                } else {
                                        DEBUG(5, ("Could not load config file: %s\n",
                                                  conf));
                                }
                                SAFE_FREE(conf);
                        }
                }
                
                if (!conf_loaded) {
                        /*
                         * Well, if that failed, try the get_dyn_CONFIGFILE
                         * Which points to the standard locn, and if that
                         * fails, silently ignore it and use the internal
                         * defaults ...
                         */
                        
                        if (!lp_load(get_dyn_CONFIGFILE(), True, False, False, False)) {
                                DEBUG(5, ("Could not load config file: %s\n",
                                          get_dyn_CONFIGFILE()));
                        } else if (home) {
                                char *conf;
                                /*
                                 * We loaded the global config file.  Now lets
                                 * load user-specific modifications to the
                                 * global config.
                                 */
                                if (asprintf(&conf,
                                             "%s/.smb/smb.conf.append",
                                             home) > 0) {
                                        if (!lp_load(conf, True, False, False, False)) {
                                                DEBUG(10,
                                                      ("Could not append config file: "
                                                       "%s\n",
                                                       conf));
                                        }
                                        SAFE_FREE(conf);
                                }
                        }
                }
                
                load_interfaces();  /* Load the list of interfaces ... */
                
                reopen_logs();  /* Get logging working ... */
                
                /*
                 * Block SIGPIPE (from lib/util_sock.c: write())
                 * It is not needed and should not stop execution
                 */
                BlockSignals(True, SIGPIPE);
                
                /* Done with one-time initialisation */
                SMBC_initialized = 1;
                
                TALLOC_FREE(frame);
        }
        
        if (!context->config.user) {
                /*
                 * FIXME: Is this the best way to get the user info?
                 */
                user = getenv("USER");
                /* walk around as "guest" if no username can be found */
                if (!user) context->config.user = SMB_STRDUP("guest");
                else context->config.user = SMB_STRDUP(user);
        }
        
        if (!context->config.netbios_name) {
                /*
                 * We try to get our netbios name from the config. If that
                 * fails we fall back on constructing our netbios name from
                 * our hostname etc
                 */
                if (global_myname()) {
                        context->config.netbios_name = SMB_STRDUP(global_myname());
                }
                else {
                        /*
                         * Hmmm, I want to get hostname as well, but I am too
                         * lazy for the moment
                         */
                        pid = sys_getpid();
                        context->config.netbios_name = (char *)SMB_MALLOC(17);
                        if (!context->config.netbios_name) {
                                errno = ENOMEM;
                                return NULL;
                        }
                        slprintf(context->config.netbios_name, 16,
                                 "smbc%s%d", context->config.user, pid);
                }
        }
        
        DEBUG(1, ("Using netbios name %s.\n", context->config.netbios_name));
        
        if (!context->config.workgroup) {
                if (lp_workgroup()) {
                        context->config.workgroup = SMB_STRDUP(lp_workgroup());
                }
                else {
                        /* TODO: Think about a decent default workgroup */
                        context->config.workgroup = SMB_STRDUP("samba");
                }
        }
        
        DEBUG(1, ("Using workgroup %s.\n", context->config.workgroup));
        
        /* shortest timeout is 1 second */
        if (context->config.timeout > 0 && context->config.timeout < 1000)
                context->config.timeout = 1000;
        
        /*
         * FIXME: Should we check the function pointers here?
         */
        
        context->internal->initialized = True;
        
        return context;
}


/* Return the verion of samba, and thus libsmbclient */
const char *
smbc_version(void)
{
        return samba_version_string();
}


/** Get the netbios name used for making connections */
char *
smbc_getNetbiosName(SMBCCTX *c)
{
        return c->config.netbios_name;
}

/** Set the netbios name used for making connections */
void
smbc_setNetbiosName(SMBCCTX *c, char * netbios_name)
{
        c->config.netbios_name = netbios_name;
}

/** Get the workgroup used for making connections */
char *
smbc_getWorkgroup(SMBCCTX *c)
{
        return c->config.workgroup;
}

/** Set the workgroup used for making connections */
void
smbc_setWorkgroup(SMBCCTX *c, char * workgroup)
{
        c->config.workgroup = workgroup;
}

/** Get the username used for making connections */
char *
smbc_getUser(SMBCCTX *c)
{
        return c->config.user;
}

/** Set the username used for making connections */
void
smbc_setUser(SMBCCTX *c, char * user)
{
        c->config.user = user;
}

/** Get the debug level */
int
smbc_getDebug(SMBCCTX *c)
{
        return c->config.debug;
}

/** Set the debug level */
void
smbc_setDebug(SMBCCTX *c, int debug)
{
        c->config.debug = debug;
}

/**
 * Get the timeout used for waiting on connections and response data
 * (in milliseconds)
 */
int
smbc_getTimeout(SMBCCTX *c)
{
        return c->config.timeout;
}

/**
 * Set the timeout used for waiting on connections and response data
 * (in milliseconds)
 */
void
smbc_setTimeout(SMBCCTX *c, int timeout)
{
        c->config.timeout = timeout;
}

/** Get whether to log to standard error instead of standard output */
smbc_bool
smbc_getOptionDebugToStderr(SMBCCTX *c)
{
        return c->internal->debug_stderr;
}

/** Set whether to log to standard error instead of standard output */
void
smbc_setOptionDebugToStderr(SMBCCTX *c, smbc_bool b)
{
        c->internal->debug_stderr = b;
}

/**
 * Get whether to use new-style time attribute names, e.g. WRITE_TIME rather
 * than the old-style names such as M_TIME.  This allows also setting/getting
 * CREATE_TIME which was previously unimplemented.  (Note that the old C_TIME
 * was supposed to be CHANGE_TIME but was confused and sometimes referred to
 * CREATE_TIME.)
 */
smbc_bool
smbc_getOptionFullTimeNames(SMBCCTX *c)
{
        return c->internal->full_time_names;
}

/**
 * Set whether to use new-style time attribute names, e.g. WRITE_TIME rather
 * than the old-style names such as M_TIME.  This allows also setting/getting
 * CREATE_TIME which was previously unimplemented.  (Note that the old C_TIME
 * was supposed to be CHANGE_TIME but was confused and sometimes referred to
 * CREATE_TIME.)
 */
void
smbc_setOptionFullTimeNames(SMBCCTX *c, smbc_bool b)
{
        c->internal->full_time_names = b;
}

/**
 * Get the share mode to use for files opened with SMBC_open_ctx().  The
 * default is SMBC_SHAREMODE_DENY_NONE.
 */
smbc_share_mode
smbc_getOptionOpenShareMode(SMBCCTX *c)
{
        return c->internal->share_mode;
}

/**
 * Set the share mode to use for files opened with SMBC_open_ctx().  The
 * default is SMBC_SHAREMODE_DENY_NONE.
 */
void
smbc_setOptionOpenShareMode(SMBCCTX *c, smbc_share_mode share_mode)
{
        c->internal->share_mode = share_mode;
}

/** Retrieve a previously set user data handle */
void *
smbc_getOptionUserData(SMBCCTX *c)
{
        return c->internal->user_data;
}

/** Save a user data handle */
void
smbc_setOptionUserData(SMBCCTX *c, void *user_data)
{
        c->internal->user_data = user_data;
}

/** Get the encoded value for encryption level. */
smbc_smb_encrypt_level
smbc_getOptionSmbEncryptionLevel(SMBCCTX *c)
{
        return c->internal->smb_encryption_level;
}

/** Set the encoded value for encryption level. */
void
smbc_setOptionSmbEncryptionLevel(SMBCCTX *c, smbc_smb_encrypt_level level)
{
        c->internal->smb_encryption_level = level;
}

/**
 * Get from how many local master browsers should the list of workgroups be
 * retrieved.  It can take up to 12 minutes or longer after a server becomes a
 * local master browser, for it to have the entire browse list (the list of
 * workgroups/domains) from an entire network.  Since a client never knows
 * which local master browser will be found first, the one which is found
 * first and used to retrieve a browse list may have an incomplete or empty
 * browse list.  By requesting the browse list from multiple local master
 * browsers, a more complete list can be generated.  For small networks (few
 * workgroups), it is recommended that this value be set to 0, causing the
 * browse lists from all found local master browsers to be retrieved and
 * merged.  For networks with many workgroups, a suitable value for this
 * variable is probably somewhere around 3. (Default: 3).
 */
int
smbc_getOptionBrowseMaxLmbCount(SMBCCTX *c)
{
        return c->options.browse_max_lmb_count;
}

/**
 * Set from how many local master browsers should the list of workgroups be
 * retrieved.  It can take up to 12 minutes or longer after a server becomes a
 * local master browser, for it to have the entire browse list (the list of
 * workgroups/domains) from an entire network.  Since a client never knows
 * which local master browser will be found first, the one which is found
 * first and used to retrieve a browse list may have an incomplete or empty
 * browse list.  By requesting the browse list from multiple local master
 * browsers, a more complete list can be generated.  For small networks (few
 * workgroups), it is recommended that this value be set to 0, causing the
 * browse lists from all found local master browsers to be retrieved and
 * merged.  For networks with many workgroups, a suitable value for this
 * variable is probably somewhere around 3. (Default: 3).
 */
void
smbc_setOptionBrowseMaxLmbCount(SMBCCTX *c, int count)
{
        c->options.browse_max_lmb_count = count;
}

/**
 * Get whether to url-encode readdir entries.
 *
 * There is a difference in the desired return strings from
 * smbc_readdir() depending upon whether the filenames are to
 * be displayed to the user, or whether they are to be
 * appended to the path name passed to smbc_opendir() to call
 * a further smbc_ function (e.g. open the file with
 * smbc_open()).  In the former case, the filename should be
 * in "human readable" form.  In the latter case, the smbc_
 * functions expect a URL which must be url-encoded.  Those
 * functions decode the URL.  If, for example, smbc_readdir()
 * returned a file name of "abc%20def.txt", passing a path
 * with this file name attached to smbc_open() would cause
 * smbc_open to attempt to open the file "abc def.txt" since
 * the %20 is decoded into a space.
 *
 * Set this option to True if the names returned by
 * smbc_readdir() should be url-encoded such that they can be
 * passed back to another smbc_ call.  Set it to False if the
 * names returned by smbc_readdir() are to be presented to the
 * user.
 *
 * For backwards compatibility, this option defaults to False.
 */
smbc_bool
smbc_getOptionUrlEncodeReaddirEntries(SMBCCTX *c)
{
        return c->options.urlencode_readdir_entries;
}

/**
 * Set whether to url-encode readdir entries.
 *
 * There is a difference in the desired return strings from
 * smbc_readdir() depending upon whether the filenames are to
 * be displayed to the user, or whether they are to be
 * appended to the path name passed to smbc_opendir() to call
 * a further smbc_ function (e.g. open the file with
 * smbc_open()).  In the former case, the filename should be
 * in "human readable" form.  In the latter case, the smbc_
 * functions expect a URL which must be url-encoded.  Those
 * functions decode the URL.  If, for example, smbc_readdir()
 * returned a file name of "abc%20def.txt", passing a path
 * with this file name attached to smbc_open() would cause
 * smbc_open to attempt to open the file "abc def.txt" since
 * the %20 is decoded into a space.
 *
 * Set this option to True if the names returned by
 * smbc_readdir() should be url-encoded such that they can be
 * passed back to another smbc_ call.  Set it to False if the
 * names returned by smbc_readdir() are to be presented to the
 * user.
 *
 * For backwards compatibility, this option defaults to False.
 */
void
smbc_setOptionUrlEncodeReaddirEntries(SMBCCTX *c, smbc_bool b)
{
        c->options.urlencode_readdir_entries = b;
}

/**
 * Get whether to use the same connection for all shares on a server.
 *
 * Some Windows versions appear to have a limit to the number
 * of concurrent SESSIONs and/or TREE CONNECTions.  In
 * one-shot programs (i.e. the program runs and then quickly
 * ends, thereby shutting down all connections), it is
 * probably reasonable to establish a new connection for each
 * share.  In long-running applications, the limitation can be
 * avoided by using only a single connection to each server,
 * and issuing a new TREE CONNECT when the share is accessed.
 */
smbc_bool
smbc_getOptionOneSharePerServer(SMBCCTX *c)
{
        return c->options.one_share_per_server;
}

/**
 * Set whether to use the same connection for all shares on a server.
 *
 * Some Windows versions appear to have a limit to the number
 * of concurrent SESSIONs and/or TREE CONNECTions.  In
 * one-shot programs (i.e. the program runs and then quickly
 * ends, thereby shutting down all connections), it is
 * probably reasonable to establish a new connection for each
 * share.  In long-running applications, the limitation can be
 * avoided by using only a single connection to each server,
 * and issuing a new TREE CONNECT when the share is accessed.
 */
void
smbc_setOptionOneSharePerServer(SMBCCTX *c, smbc_bool b)
{
        c->options.one_share_per_server = b;
}

/** Get whether to enable use of kerberos */
smbc_bool
smbc_getOptionUseKerberos(SMBCCTX *c)
{
        return c->flags.bits & SMB_CTX_FLAG_USE_KERBEROS ? True : False;
}

/** Set whether to enable use of kerberos */
void
smbc_setOptionUseKerberos(SMBCCTX *c, smbc_bool b)
{
        if (b) {
                c->flags.bits |= SMB_CTX_FLAG_USE_KERBEROS;
        } else {
                c->flags.bits &= ~SMB_CTX_FLAG_USE_KERBEROS;
        }
}

/** Get whether to fallback after kerberos */
smbc_bool
smbc_getOptionFallbackAfterKerberos(SMBCCTX *c)
{
        return c->flags.bits & SMB_CTX_FLAG_FALLBACK_AFTER_KERBEROS ? True : False;
}

/** Set whether to fallback after kerberos */
void
smbc_setOptionFallbackAfterKerberos(SMBCCTX *c, smbc_bool b)
{
        if (b) {
                c->flags.bits |= SMB_CTX_FLAG_FALLBACK_AFTER_KERBEROS;
        } else {
                c->flags.bits &= ~SMB_CTX_FLAG_FALLBACK_AFTER_KERBEROS;
        }
}

/** Get whether to automatically select anonymous login */
smbc_bool
smbc_getOptionNoAutoAnonymousLogin(SMBCCTX *c)
{
        return c->flags.bits & SMBCCTX_FLAG_NO_AUTO_ANONYMOUS_LOGON ? True : False;
}

/** Set whether to automatically select anonymous login */
void
smbc_setOptionNoAutoAnonymousLogin(SMBCCTX *c, smbc_bool b)
{
        if (b) {
                c->flags.bits |= SMBCCTX_FLAG_NO_AUTO_ANONYMOUS_LOGON;
        } else {
                c->flags.bits &= ~SMBCCTX_FLAG_NO_AUTO_ANONYMOUS_LOGON;
        }
}

/** Get the function for obtaining authentication data */
smbc_get_auth_data_fn
smbc_getFunctionAuthData(SMBCCTX *c)
{
        return c->server.get_auth_data_fn;
}

/** Set the function for obtaining authentication data */
void
smbc_setFunctionAuthData(SMBCCTX *c, smbc_get_auth_data_fn fn)
{
        c->internal->auth_fn_with_context = NULL;
        c->server.get_auth_data_fn = fn;
}

/** Get the new-style authentication function which includes the context. */
smbc_get_auth_data_with_context_fn
smbc_getFunctionAuthDataWithContext(SMBCCTX *c)
{
        return c->internal->auth_fn_with_context;
}

/** Set the new-style authentication function which includes the context. */
void
smbc_setFunctionAuthDataWithContext(SMBCCTX *c,
                                    smbc_get_auth_data_with_context_fn fn)
{
        c->server.get_auth_data_fn = NULL;
        c->internal->auth_fn_with_context = fn;
}

/** Get the function for checking if a server is still good */
smbc_check_server_fn
smbc_getFunctionCheckServer(SMBCCTX *c)
{
        return c->server.check_server_fn;
}

/** Set the function for checking if a server is still good */
void
smbc_setFunctionCheckServer(SMBCCTX *c, smbc_check_server_fn fn)
{
        c->server.check_server_fn = fn;
}

/** Get the function for removing a server if unused */
smbc_remove_unused_server_fn
smbc_getFunctionRemoveUnusedServer(SMBCCTX *c)
{
        return c->server.remove_unused_server_fn;
}

/** Set the function for removing a server if unused */
void
smbc_setFunctionRemoveUnusedServer(SMBCCTX *c,
                                   smbc_remove_unused_server_fn fn)
{
        c->server.remove_unused_server_fn = fn;
}

/** Get the function to store private data of the server cache */
struct
smbc_server_cache * smbc_getServerCacheData(SMBCCTX *c)
{
        return c->cache.server_cache_data;
}

/** Set the function to store private data of the server cache */
void
smbc_setServerCacheData(SMBCCTX *c, struct smbc_server_cache * cache)
{
        c->cache.server_cache_data = cache;
}


/** Get the function for adding a cached server */
smbc_add_cached_srv_fn
smbc_getFunctionAddCachedServer(SMBCCTX *c)
{
        return c->cache.add_cached_server_fn;
}

/** Set the function for adding a cached server */
void
smbc_setFunctionAddCachedServer(SMBCCTX *c, smbc_add_cached_srv_fn fn)
{
        c->cache.add_cached_server_fn = fn;
}

/** Get the function for server cache lookup */
smbc_get_cached_srv_fn
smbc_getFunctionGetCachedServer(SMBCCTX *c)
{
        return c->cache.get_cached_server_fn;
}

/** Set the function for server cache lookup */
void
smbc_setFunctionGetCachedServer(SMBCCTX *c, smbc_get_cached_srv_fn fn)
{
        c->cache.get_cached_server_fn = fn;
}

/** Get the function for server cache removal */
smbc_remove_cached_srv_fn
smbc_getFunctionRemoveCachedServer(SMBCCTX *c)
{
        return c->cache.remove_cached_server_fn;
}

/** Set the function for server cache removal */
void
smbc_setFunctionRemoveCachedServer(SMBCCTX *c,
                                   smbc_remove_cached_srv_fn fn)
{
        c->cache.remove_cached_server_fn = fn;
}

/**
 * Get the function for server cache purging.  This function tries to
 * remove all cached servers (e.g. on disconnect)
 */
smbc_purge_cached_srv_fn
smbc_getFunctionPurgeCachedServers(SMBCCTX *c)
{
        return c->cache.purge_cached_servers_fn;
}

/**
 * Set the function for server cache purging.  This function tries to
 * remove all cached servers (e.g. on disconnect)
 */
void
smbc_setFunctionPurgeCachedServers(SMBCCTX *c, smbc_purge_cached_srv_fn fn)
{
        c->cache.purge_cached_servers_fn = fn;
}

/**
 * Callable functions for files.
 */

smbc_open_fn
smbc_getFunctionOpen(SMBCCTX *c)
{
        return c->posix_emu.open_fn;
}

void
smbc_setFunctionOpen(SMBCCTX *c, smbc_open_fn fn)
{
        c->posix_emu.open_fn = fn;
}

smbc_creat_fn
smbc_getFunctionCreat(SMBCCTX *c)
{
        return c->posix_emu.creat_fn;
}

void
smbc_setFunctionCreat(SMBCCTX *c, smbc_creat_fn fn)
{
        c->posix_emu.creat_fn = fn;
}

smbc_read_fn
smbc_getFunctionRead(SMBCCTX *c)
{
        return c->posix_emu.read_fn;
}

void
smbc_setFunctionRead(SMBCCTX *c, smbc_read_fn fn)
{
        c->posix_emu.read_fn = fn;
}

smbc_write_fn
smbc_getFunctionWrite(SMBCCTX *c)
{
        return c->posix_emu.write_fn;
}

void
smbc_setFunctionWrite(SMBCCTX *c, smbc_write_fn fn)
{
        c->posix_emu.write_fn = fn;
}

smbc_unlink_fn
smbc_getFunctionUnlink(SMBCCTX *c)
{
        return c->posix_emu.unlink_fn;
}

void
smbc_setFunctionUnlink(SMBCCTX *c, smbc_unlink_fn fn)
{
        c->posix_emu.unlink_fn = fn;
}

smbc_rename_fn
smbc_getFunctionRename(SMBCCTX *c)
{
        return c->posix_emu.rename_fn;
}

void
smbc_setFunctionRename(SMBCCTX *c, smbc_rename_fn fn)
{
        c->posix_emu.rename_fn = fn;
}

smbc_lseek_fn
smbc_getFunctionLseek(SMBCCTX *c)
{
        return c->posix_emu.lseek_fn;
}

void
smbc_setFunctionLseek(SMBCCTX *c, smbc_lseek_fn fn)
{
        c->posix_emu.lseek_fn = fn;
}

smbc_stat_fn
smbc_getFunctionStat(SMBCCTX *c)
{
        return c->posix_emu.stat_fn;
}

void
smbc_setFunctionStat(SMBCCTX *c, smbc_stat_fn fn)
{
        c->posix_emu.stat_fn = fn;
}

smbc_fstat_fn
smbc_getFunctionFstat(SMBCCTX *c)
{
        return c->posix_emu.fstat_fn;
}

void
smbc_setFunctionFstat(SMBCCTX *c, smbc_fstat_fn fn)
{
        c->posix_emu.fstat_fn = fn;
}

smbc_ftruncate_fn
smbc_getFunctionFtruncate(SMBCCTX *c)
{
        return c->internal->posix_emu.ftruncate_fn;
}

void
smbc_setFunctionFtruncate(SMBCCTX *c, smbc_ftruncate_fn fn)
{
        c->internal->posix_emu.ftruncate_fn = fn;
}

smbc_close_fn
smbc_getFunctionClose(SMBCCTX *c)
{
        return c->posix_emu.close_fn;
}

void
smbc_setFunctionClose(SMBCCTX *c, smbc_close_fn fn)
{
        c->posix_emu.close_fn = fn;
}


/**
 * Callable functions for directories.
 */

smbc_opendir_fn
smbc_getFunctionOpendir(SMBCCTX *c)
{
        return c->posix_emu.opendir_fn;
}

void
smbc_setFunctionOpendir(SMBCCTX *c, smbc_opendir_fn fn)
{
        c->posix_emu.opendir_fn = fn;
}

smbc_closedir_fn
smbc_getFunctionClosedir(SMBCCTX *c)
{
        return c->posix_emu.closedir_fn;
}

void
smbc_setFunctionClosedir(SMBCCTX *c, smbc_closedir_fn fn)
{
        c->posix_emu.closedir_fn = fn;
}

smbc_readdir_fn
smbc_getFunctionReaddir(SMBCCTX *c)
{
        return c->posix_emu.readdir_fn;
}

void
smbc_setFunctionReaddir(SMBCCTX *c, smbc_readdir_fn fn)
{
        c->posix_emu.readdir_fn = fn;
}

smbc_getdents_fn
smbc_getFunctionGetdents(SMBCCTX *c)
{
        return c->posix_emu.getdents_fn;
}

void
smbc_setFunctionGetdents(SMBCCTX *c, smbc_getdents_fn fn)
{
        c->posix_emu.getdents_fn = fn;
}

smbc_mkdir_fn
smbc_getFunctionMkdir(SMBCCTX *c)
{
        return c->posix_emu.mkdir_fn;
}

void
smbc_setFunctionMkdir(SMBCCTX *c, smbc_mkdir_fn fn)
{
        c->posix_emu.mkdir_fn = fn;
}

smbc_rmdir_fn
smbc_getFunctionRmdir(SMBCCTX *c)
{
        return c->posix_emu.rmdir_fn;
}

void
smbc_setFunctionRmdir(SMBCCTX *c, smbc_rmdir_fn fn)
{
        c->posix_emu.rmdir_fn = fn;
}

smbc_telldir_fn
smbc_getFunctionTelldir(SMBCCTX *c)
{
        return c->posix_emu.telldir_fn;
}

void
smbc_setFunctionTelldir(SMBCCTX *c, smbc_telldir_fn fn)
{
        c->posix_emu.telldir_fn = fn;
}

smbc_lseekdir_fn
smbc_getFunctionLseekdir(SMBCCTX *c)
{
        return c->posix_emu.lseekdir_fn;
}

void
smbc_setFunctionLseekdir(SMBCCTX *c, smbc_lseekdir_fn fn)
{
        c->posix_emu.lseekdir_fn = fn;
}

smbc_fstatdir_fn
smbc_getFunctionFstatdir(SMBCCTX *c)
{
        return c->posix_emu.fstatdir_fn;
}

void
smbc_setFunctionFstatdir(SMBCCTX *c, smbc_fstatdir_fn fn)
{
        c->posix_emu.fstatdir_fn = fn;
}


/**
 * Callable functions applicable to both files and directories.
 */

smbc_chmod_fn
smbc_getFunctionChmod(SMBCCTX *c)
{
        return c->posix_emu.chmod_fn;
}

void
smbc_setFunctionChmod(SMBCCTX *c, smbc_chmod_fn fn)
{
        c->posix_emu.chmod_fn = fn;
}

smbc_utimes_fn
smbc_getFunctionUtimes(SMBCCTX *c)
{
        return c->posix_emu.utimes_fn;
}

void
smbc_setFunctionUtimes(SMBCCTX *c, smbc_utimes_fn fn)
{
        c->posix_emu.utimes_fn = fn;
}

smbc_setxattr_fn
smbc_getFunctionSetxattr(SMBCCTX *c)
{
        return c->posix_emu.setxattr_fn;
}

void
smbc_setFunctionSetxattr(SMBCCTX *c, smbc_setxattr_fn fn)
{
        c->posix_emu.setxattr_fn = fn;
}

smbc_getxattr_fn
smbc_getFunctionGetxattr(SMBCCTX *c)
{
        return c->posix_emu.getxattr_fn;
}

void
smbc_setFunctionGetxattr(SMBCCTX *c, smbc_getxattr_fn fn)
{
        c->posix_emu.getxattr_fn = fn;
}

smbc_removexattr_fn
smbc_getFunctionRemovexattr(SMBCCTX *c)
{
        return c->posix_emu.removexattr_fn;
}

void
smbc_setFunctionRemovexattr(SMBCCTX *c, smbc_removexattr_fn fn)
{
        c->posix_emu.removexattr_fn = fn;
}

smbc_listxattr_fn
smbc_getFunctionListxattr(SMBCCTX *c)
{
        return c->posix_emu.listxattr_fn;
}

void
smbc_setFunctionListxattr(SMBCCTX *c, smbc_listxattr_fn fn)
{
        c->posix_emu.listxattr_fn = fn;
}


/**
 * Callable functions related to printing
 */

smbc_print_file_fn
smbc_getFunctionPrintFile(SMBCCTX *c)
{
        return c->printing.print_file_fn;
}

void
smbc_setFunctionPrintFile(SMBCCTX *c, smbc_print_file_fn fn)
{
        c->printing.print_file_fn = fn;
}

smbc_open_print_job_fn
smbc_getFunctionOpenPrintJob(SMBCCTX *c)
{
        return c->printing.open_print_job_fn;
}

void
smbc_setFunctionOpenPrintJob(SMBCCTX *c,
                             smbc_open_print_job_fn fn)
{
        c->printing.open_print_job_fn = fn;
}

smbc_list_print_jobs_fn
smbc_getFunctionListPrintJobs(SMBCCTX *c)
{
        return c->printing.list_print_jobs_fn;
}

void
smbc_setFunctionListPrintJobs(SMBCCTX *c,
                              smbc_list_print_jobs_fn fn)
{
        c->printing.list_print_jobs_fn = fn;
}

smbc_unlink_print_job_fn
smbc_getFunctionUnlinkPrintJob(SMBCCTX *c)
{
        return c->printing.unlink_print_job_fn;
}

void
smbc_setFunctionUnlinkPrintJob(SMBCCTX *c,
                               smbc_unlink_print_job_fn fn)
{
        c->printing.unlink_print_job_fn = fn;
}

