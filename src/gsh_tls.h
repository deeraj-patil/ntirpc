// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2025, IBM . All rights reserved.
 * Author: Deeraj Patil <deeraj.patil@ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.  see <http://www.gnu.org/licenses/
 *
 * ---------------------------------------
 */

/**
 * @file gsh_tls.h
 */


#include <fcntl.h>
#include <errno.h>
#include "strl.h"
#include "rpc/svc.h"
#include "rpc/types.h"
#include "svc_internal.h"
#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

#ifdef USE_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#endif

#define GSH_SESSION_UNKNOWN_ERROR -1
#define GSH_SESSION_CLOSED_ADRUPTLY -2
#define GSH_TLS_HANDSHAKE_FAILED -3

#define DPP_INIT "[Init Path]:"
#define DPP_DISPATCH "[Dispatch]:"
#define DPP_HANDSHAKE "[Handshake Path]:"
#define DPP_SHUTDOWN "[Handshake Path]:"
#define DPP_UNKNOWN " "

#define LogCritTLS(component, format, ...)                                   \
	__warnx(TIRPC_DEBUG_FLAG_ERROR, "[TLS]:%s:%s:%d " format, component, \
		__func__, __LINE__, ##__VA_ARGS__)

#define LogWarnTLS(component, format, ...)                                  \
	__warnx(TIRPC_DEBUG_FLAG_WARN, "[TLS]:%s:%s:%d " format, component, \
		__func__, __LINE__, ##__VA_ARGS__)

#define LogEventTLS(component, format, ...)                                  \
	__warnx(TIRPC_DEBUG_FLAG_EVENT, "[TLS]:%s:%s:%d " format, component, \
		__func__, __LINE__, ##__VA_ARGS__)

#define LogDebugTLS(component, format, ...)                                  \
	if (tls_config.debug) 					\
		__warnx(TIRPC_DEBUG_FLAG_EVENT, "[TLS]:%s:%s:%d " format,	\
		component, __func__, __LINE__, ##__VA_ARGS__)

/* TLS context structure */
typedef struct gsh_tls_ctx {
#ifdef USE_OPENSSL
	struct ssl_st *ssl;
	struct ssl_ctx_st *ctx;
#endif

#ifdef USE_GNUTLS
	//struct gnutls_session_int *session;
	//struct gnutls_certificate_credentials_st *cred;
	gnutls_session_t session; /* GnuTLS session */
	gnutls_certificate_credentials_t creds; /* GnuTLS credentials */
#endif

	pthread_mutex_t ctx_lock;
	bool handshake_complete;
	int fd;
} gsh_tls_ctx_t;

/* TLS configuration structure */
typedef struct gsh_tls_config {
	bool enabled;
	char *cert_file;
	char *key_file;
	char *ca_file;
	char *ciphers;
	char *min_version;
	time_t session_timeout;
	bool ktls; /* Enable kernel TLS if available */
	bool debug;
} gsh_tls_config_t;

extern gsh_tls_config_t tls_config;
/*
 * Check the packet is handshake msg
 * NOTE: This is stunnel like TLS handshake request handling
 *       This internally does handshake if this is handshake msg.
 * @param xprt 	       Xprt for which handshake msg needs to be checked.
 * @return             true on handshake msg,
 * 		       false if handshake failed or not handshake msg.
 * */
bool is_handshake_msg(SVCXPRT *xprt);
