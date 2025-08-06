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
 * @file gsh_tls_transport.c
 * @brief Plugging module for entertaining diffrent backend TLS libs.
 * Implementation is done in such a way that, if any user wants to add support
 * for more TLS libs, it should be seamless.
 *
 * Routines used for entertaining TLS in NFS-Ganesha.
 *
 *
 */

#include "gsh_tls.h"

extern gsh_tls_ctx_t *gsh_tls_ctx_init(int fd);
extern bool gsh_tls_handshake(gsh_tls_ctx_t *ctx);
extern int gsh_tls_recv(gsh_tls_ctx_t *ctx, void *buf, size_t len, int flags);
extern int gsh_tls_send(gsh_tls_ctx_t *ctx, const struct msghdr *msg, int flags);
extern bool gsh_tls_close(gsh_tls_ctx_t *ctx);
extern bool gsh_tls_verify_peer(gsh_tls_ctx_t *ctx, char *peer_identity,
		                         size_t id_size);
extern bool gsh_tls_key_update(gsh_tls_ctx_t *ctx);
extern bool get_tls_type(gsh_tls_ctx_t *ctx);

/* Initialize TLS for a transport */
bool xp_tls_init_impl(SVCXPRT *xprt)
{
	int ret;

	LogDebugTLS(DPP_DISPATCH, "xprt:%p fd:%d", xprt, xprt->xp_fd);
	if (!xprt || !xprt->xp_tls.tls_enabled) {
		LogEventTLS(DPP_HANDSHAKE, "TLS not enabled for this transport");
		ret = false;
		goto out;
	}

	pthread_mutex_lock(&(xprt->xp_tls.tls_lock));
	/* Create TLS context if not already created */
	if (!xprt->xp_tls.tls_ctx) {
		xprt->xp_tls.tls_ctx = gsh_tls_ctx_init(xprt->xp_fd);
		if (!xprt->xp_tls.tls_ctx) {
			LogCritTLS(DPP_HANDSHAKE,
				   "Failed to initialize TLS context for fd %d",
				   xprt->xp_fd);
			ret = false;
			goto out;
		}
	}

	if (xprt->xp_tls.tls_established) {
		LogDebugTLS(DPP_HANDSHAKE,
			    "TLS already established for this transport");
		ret = true;
		goto out;
	}

	/* Perform TLS handshake */
	if (!gsh_tls_handshake(xprt->xp_tls.tls_ctx)) {
		LogWarnTLS(DPP_HANDSHAKE, "TLS handshake failed for fd %d",
			   xprt->xp_fd);
		ret = false;
		goto out;
	}

	xprt->xp_tls.mtls = get_tls_type(xprt->xp_tls.tls_ctx);
	LogWarnTLS(DPP_HANDSHAKE, "fd %d MTLS:%d",
					xprt->xp_fd, xprt->xp_tls.mtls);
	/* Verify client certificate */
	char peer_identity[512];
	if (!gsh_tls_verify_peer(xprt->xp_tls.tls_ctx, peer_identity,
				 sizeof(peer_identity))) {
		LogWarnTLS(DPP_HANDSHAKE,
			   "Client certificate verification failed for fd %d",
			   xprt->xp_fd);
		ret = false;
		goto out;
	}

	xprt->xp_tls.tls_established = true;
	LogEventTLS(DPP_HANDSHAKE,
		    "TLS connection established for fd %d, ", xprt->xp_fd);

	ret = true;
out:
	pthread_mutex_unlock(&(xprt->xp_tls.tls_lock));
	return ret;
}

/* Receive TLS decoded data */
int xp_tls_recv_impl(SVCXPRT *xprt, void *buf, size_t len, int flags)
{
	int ret;
	LogDebugTLS(DPP_DISPATCH, "xprt:%p fd:%d", xprt, xprt->xp_fd);
	if (!xprt || !xprt->xp_tls.tls_ctx || !buf || len <= 0) {
		LogDebugTLS(DPP_DISPATCH, "Invalid TLS context for recv");
		return -1;
	}

	pthread_mutex_lock(&(xprt->xp_tls.tls_lock));
	ret = gsh_tls_recv(xprt->xp_tls.tls_ctx, buf, len, flags);
	pthread_mutex_unlock(&(xprt->xp_tls.tls_lock));

	if (GSH_SESSION_CLOSED_ADRUPTLY == ret) {
		LogWarnTLS(DPP_DISPATCH, "Session Closed adruptly");
		return -1;
	}
	return ret;
}

/* Send data over TLS */
int xp_tls_send_impl(SVCXPRT *xprt, const struct msghdr *msg, int flags)
{
	int ret = 0;
	LogDebugTLS(DPP_DISPATCH, "xprt:%p fd:%d", xprt, xprt->xp_fd);
	if (!xprt || !xprt->xp_tls.tls_ctx || !msg || !msg->msg_iov ||
	    msg->msg_iovlen <= 0) {
		LogDebugTLS(DPP_DISPATCH, "Invalid TLS context for send");
		return -1;
	}

	pthread_mutex_lock(&(xprt->xp_tls.tls_lock));
	ret = gsh_tls_send(xprt->xp_tls.tls_ctx, msg, flags);
	pthread_mutex_unlock(&(xprt->xp_tls.tls_lock));

	if (GSH_SESSION_CLOSED_ADRUPTLY == ret) {
		LogWarnTLS(DPP_DISPATCH, "Session Closed adruptly");
		return -1;
	}

	return ret;
}

/* Reset the TLS specific data in xprt */
void svc_tls_reset_xprt(SVCXPRT *xprt)
{
	xprt->xp_ops->xp_tls_recv = NULL;
	xprt->xp_ops->xp_tls_send = NULL;
	xprt->xp_ops->xp_tls_close = NULL;
	xprt->xp_tls.tls_enabled = false;
	xprt->xp_tls.tls_ctx = NULL;
	xprt->xp_tls.tls_established = false;
	xprt->xp_tls.mtls =false;
	xprt->xp_tls.not_first_packet = false;
}

/* Close TLS connection */
void xp_tls_close_impl(SVCXPRT *xprt)
{
	if (!xprt || !xprt->xp_tls.tls_ctx) {
		return; /* Nothing to close */
	}
	LogDebugTLS(DPP_DISPATCH, "xprt:%p fd:%d", xprt, xprt->xp_fd);
	pthread_mutex_lock(&(xprt->xp_tls.tls_lock));
	gsh_tls_close(xprt->xp_tls.tls_ctx);
	svc_tls_reset_xprt(xprt);
	pthread_mutex_unlock(&(xprt->xp_tls.tls_lock));
	return;
}

/* Export TLS transport operations */
struct xp_ops_tls {
	int (*xp_tls_recv)(SVCXPRT *, void *, size_t, int flags);
	int (*xp_tls_send)(SVCXPRT *, const struct msghdr *msg, int flags);
	void (*xp_tls_close)(SVCXPRT *);
} xp_ops_tls = { .xp_tls_recv = xp_tls_recv_impl,
		 .xp_tls_send = xp_tls_send_impl,
		 .xp_tls_close = xp_tls_close_impl };


/* Initialize TLS operations for a transport */
bool svc_tls_init_xprt(SVCXPRT *xprt)
{
	bool ret = false;
	if (!xprt) {
		return ret;
	}
	LogEventTLS(DPP_HANDSHAKE, "xprt:%p fd:%d", xprt, xprt->xp_fd);
	xprt->xp_ops->xp_tls_recv = xp_ops_tls.xp_tls_recv;
	xprt->xp_ops->xp_tls_send = xp_ops_tls.xp_tls_send;
	xprt->xp_ops->xp_tls_close = xp_ops_tls.xp_tls_close;

	/* Initialize TLS structure */
	pthread_mutex_init(&(xprt->xp_tls.tls_lock), NULL);
	xprt->xp_tls.tls_enabled = true;
	xprt->xp_tls.tls_ctx = NULL;
	xprt->xp_tls.tls_established = false;

	ret = xp_tls_init_impl(xprt);
	if (ret == false) {
		svc_tls_reset_xprt(xprt);
		LogEventTLS(DPP_HANDSHAKE, "TLS disabled xprt:%p fd:%d", xprt, xprt->xp_fd);

	} else {
		LogEventTLS(DPP_HANDSHAKE, "TLS enabled xprt:%p fd:%d", xprt, xprt->xp_fd);
	}
	return ret;
}

static inline bool is_tls_clienthello(SVCXPRT *xprt)
{
	unsigned char peek_buf[5];
	ssize_t n = recv(xprt->xp_fd, peek_buf, sizeof(peek_buf), MSG_PEEK);
	bool ret = false;
	if (n < 5)
		return false;

	// TLS record type = 0x16 (handshake), Version = 0x0303 or higher
	if (peek_buf[0] == 0x16 && peek_buf[1] == 0x03 &&
	    (peek_buf[2] == 0x01 || peek_buf[2] == 0x03 ||
	     peek_buf[2] == 0x04)) {
		ret = svc_tls_init_xprt(xprt);
	}
	return ret;
}

bool is_handshake_msg(SVCXPRT *xprt)
{
	return is_tls_clienthello(xprt);
}
