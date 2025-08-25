
extern gsh_tls_ctx_t *gsh_tls_ctx_init(int fd, gsh_tls_cred_t *cred,
		bool is_server);
extern gsh_tls_cred_t *gsh_tls_init(const char *cert_file, const char *key_file,
		const char *ca_file, const char *ciphers,
		const char *min_version, bool ktls,
		bool debug);
extern bool gsh_tls_handshake(gsh_tls_ctx_t *ctx);
extern int gsh_tls_recv(gsh_tls_ctx_t *ctx, void *buf, size_t len, int flags);
extern int gsh_tls_send(gsh_tls_ctx_t *ctx, const struct msghdr *msg,
		int flags);
extern bool gsh_tls_close(gsh_tls_ctx_t *ctx);
extern bool gsh_tls_verify_peer(gsh_tls_ctx_t *ctx, char *peer_identity,
		size_t id_size);
extern bool gsh_tls_key_update(gsh_tls_ctx_t *ctx);
extern bool get_tls_type(gsh_tls_ctx_t *ctx);
