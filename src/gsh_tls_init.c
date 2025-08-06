#include "gsh_tls.h"

/* Forward declarations */
gsh_tls_config_t tls_config;
extern bool gsh_tls_init(const char *cert_file, const char *key_file,
                        const char *ca_file, const char *ciphers,
                        const char *min_version, bool ktls, bool debug);

/* Initialize TLS from configuration */
bool nfs_init_tls(gsh_tls_config_t from_ganesha)
{
	tls_config = from_ganesha;
	if (!tls_config.enabled) {
		LogDebugTLS(DPP_INIT, "TLS is disabled in configuration");
		return true;
	}

	LogDebugTLS(DPP_INIT, "Initializing TLS with cert=%s, key=%s, ca=%s",
		    tls_config.cert_file, tls_config.key_file,
		    tls_config.ca_file ? tls_config.ca_file : "none");

	/* Initialize TLS library */
	if (!gsh_tls_init(tls_config.cert_file, tls_config.key_file,
			  tls_config.ca_file, tls_config.ciphers,
			  tls_config.min_version, tls_config.ktls,
			  tls_config.debug)) {
		LogCritTLS(DPP_INIT, "Failed to initialize TLS");
		return false;
	}

	LogDebugTLS(DPP_INIT, "TLS initialized successfully");
	return true;
}

/* Need to extend this to shutdown path for safe cleanup */
void nfs_cleanup_tls(void)
{
	if (!tls_config.enabled)
		return;

	/* Free configuration strings */
	if (tls_config.cert_file)
		free(tls_config.cert_file);

	if (tls_config.key_file)
		free(tls_config.key_file);

	if (tls_config.ca_file)
		free(tls_config.ca_file);

	if (tls_config.ciphers)
		free(tls_config.ciphers);

	if (tls_config.min_version)
		free(tls_config.min_version);

	tls_config.cert_file = NULL;
	tls_config.key_file = NULL;
	tls_config.ca_file = NULL;
	tls_config.ciphers = NULL;
	tls_config.min_version = NULL;
	LogDebugTLS(DPP_INIT, "TLS resources cleaned up");
}
