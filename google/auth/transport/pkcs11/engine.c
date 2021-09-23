#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>

void clean_up(ENGINE *eng, EVP_PKEY *key, BIO *bio, X509 *x509) {
    if (eng) {
        ENGINE_free(eng);
    }
    if (key) {
        EVP_PKEY_free(key);
    }
    if (bio) {
        BIO_free(bio);
    }
    if (x509) {
        X509_free(x509);
    }
}

void report_error(const char* msg, ENGINE *eng, EVP_PKEY *key, BIO *bio, X509 *x509) {
    printf("Failing calling: %s\n", msg);
    printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
    clean_up(eng, key, bio, x509);
    abort(); // failed
}

int add_cert_key(SSL_CTX *ctx, char *cert, char *engine_id, char *so_path, char *module_path, char *key_uri)
{
    EVP_PKEY *key = NULL;
    BIO *bio = NULL;
    X509 *x509 = NULL;

    // Load key.
    ENGINE_load_builtin_engines();
    ENGINE_load_dynamic();
    ENGINE *eng = ENGINE_by_id("dynamic");
    if (!eng) {
        report_error("ENGINE_by_id", eng, key, bio, x509);
    }
    if (!ENGINE_ctrl_cmd_string(eng, "ID", engine_id, 0)) {
        report_error("load pkcs11", eng, key, bio, x509);
    }
    if (!ENGINE_ctrl_cmd_string(eng, "SO_PATH", so_path, 0)) {
        report_error("load SO path", eng, key, bio, x509);
    }
    if (!ENGINE_ctrl_cmd_string(eng, "LOAD", NULL, 0)) {
        report_error("call LOAD", eng, key, bio, x509);
    }
    if (!ENGINE_ctrl_cmd_string(eng, "MODULE_PATH", module_path, 0)) {
        report_error("load MODULE path", eng, key, bio, x509);
    }
    if (!ENGINE_init(eng)) {
        report_error("init engine", eng, key, bio, x509);
    }
    key = ENGINE_load_private_key(eng, key_uri, NULL, NULL);
    if (!key) {
        report_error("load private key", eng, key, bio, x509);
    }

    // Load cert.
    bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, cert);
    x509 = PEM_read_bio_X509(bio, NULL, 0, NULL);

    // Add cert and key to SSL context.
    SSL_CTX *casted_ctx = (SSL_CTX *)ctx;
    if (!SSL_CTX_use_certificate(casted_ctx, x509)) {
        report_error("use certificate", eng, key, bio, x509);
    }
    if (!SSL_CTX_use_PrivateKey(casted_ctx, key)) {
        report_error("use private key", eng, key, bio, x509);
    }

    clean_up(eng, key, bio, x509);

    return 1;
}