#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>
 
#include <memory>
#include <iostream>
#include <stdlib.h>

#ifdef _WIN32
#include <Python.h>
#include "signer.h"
#endif

namespace {

static bool EnableLogging = false;

void LogInfo(const std::string& message) {
  if (EnableLogging) {
    std::cout << "tls_offload.cpp: " << message << "...." << std::endl;
  }
}

typedef int (*SignFunc)(unsigned char *sig, size_t *sig_len, const unsigned char *tbs, size_t tbs_len);

template <typename T, typename Ret, Ret (*Deleter)(T *)>
struct OpenSSLDeleter {
  void operator()(T *t) const { Deleter(t); }
};
 
struct OpenSSLFreeDeleter {
  void operator()(unsigned char *buf) const { OPENSSL_free(buf); }
};
 
template <typename T, void (*Deleter)(T *)>
using OwnedOpenSSLPtr = std::unique_ptr<T, OpenSSLDeleter<T, void, Deleter>>;
template <typename T, int (*Deleter)(T *)>
using OwnedOpenSSLPtrIntRet =
    std::unique_ptr<T, OpenSSLDeleter<T, int, Deleter>>;
 
using OwnedBIO = OwnedOpenSSLPtrIntRet<BIO, BIO_free>;
using OwnedENGINE = OwnedOpenSSLPtrIntRet<ENGINE, ENGINE_free>;
using OwnedEVP_MD_CTX = OwnedOpenSSLPtr<EVP_MD_CTX, EVP_MD_CTX_free>;
using OwnedEVP_PKEY = OwnedOpenSSLPtr<EVP_PKEY, EVP_PKEY_free>;
using OwnedEVP_PKEY_METHOD =
    OwnedOpenSSLPtr<EVP_PKEY_METHOD, EVP_PKEY_meth_free>;
using OwnedSSL_CTX = OwnedOpenSSLPtr<SSL_CTX, SSL_CTX_free>;
using OwnedSSL = OwnedOpenSSLPtr<SSL, SSL_free>;
using OwnedX509_PUBKEY = OwnedOpenSSLPtr<X509_PUBKEY, X509_PUBKEY_free>;
using OwnedX509 = OwnedOpenSSLPtr<X509, X509_free>;
using OwnedOpenSSLBuffer = std::unique_ptr<uint8_t, OpenSSLFreeDeleter>;

class CustomKey {
 public:
  explicit CustomKey(SignFunc sign_func): sign_func_(sign_func) {}
 
  bool Sign(unsigned char *sig, size_t *sig_len,
            const unsigned char *tbs, size_t tbs_len) {
    return sign_func_(sig, sig_len, tbs, tbs_len);
  }
 
 public:
  SignFunc sign_func_;
};

void FreeExData(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl,
                void *argp) {
  LogInfo("calling FreeExData");
  delete static_cast<CustomKey *>(ptr);
}

static int rsa_ex_index = -1, ec_ex_index = -1;

bool InitExData() {
  rsa_ex_index = RSA_get_ex_new_index(0, nullptr, nullptr, nullptr, FreeExData);
  ec_ex_index =
      EC_KEY_get_ex_new_index(0, nullptr, nullptr, nullptr, FreeExData);
  if (rsa_ex_index < 0 || ec_ex_index < 0) {
    fprintf(stderr, "Error allocating ex data.\n");
    return false;
  }
  return true;
}
 
bool SetCustomKey(RSA *rsa, std::unique_ptr<CustomKey> key) {
  LogInfo("setting RSA custom key");
  if (!RSA_set_ex_data(rsa, rsa_ex_index, key.get())) {
    return false;
  }
  (void)key.release();
  return true;
}
 
bool SetCustomKey(EC_KEY *ec_key, std::unique_ptr<CustomKey> key) {
  LogInfo("setting EC custom key");
  if (!EC_KEY_set_ex_data(ec_key, ec_ex_index, key.get())) {
    return false;
  }
  (void)key.release();
  return true;
}
 
bool SetCustomKey(EVP_PKEY *pkey, std::unique_ptr<CustomKey> key) {
  if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    return rsa && SetCustomKey(rsa, std::move(key));
  }
  if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    return ec_key && SetCustomKey(ec_key, std::move(key));
  }
  return false;
}
 
CustomKey *GetCustomKey(const RSA *rsa) {
  LogInfo("getting RSA custom key");
  return static_cast<CustomKey*>(RSA_get_ex_data(rsa, rsa_ex_index));
}
 
CustomKey *GetCustomKey(const EC_KEY *ec_key) {
  LogInfo("getting EC custom key");
  return static_cast<CustomKey*>(EC_KEY_get_ex_data(ec_key, ec_ex_index));
}
 
CustomKey *GetCustomKey(EVP_PKEY *pkey) {
  if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
    const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    if (rsa) {
      LogInfo("rsa exists in GetCustomKey");
    } else {
      LogInfo("rsa doesn't exist in GetCustomKey");
    }
    return rsa ? GetCustomKey(rsa) : nullptr;
  }
  if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
    const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    if (ec_key) {
      LogInfo("ec_key exists in GetCustomKey");
    } else {
      LogInfo("ec_key doesn't exist in GetCustomKey");
    }
    return ec_key ? GetCustomKey(ec_key) : nullptr;
  }
  return nullptr;
}

int CustomDigestSign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *sig_len,
                     const unsigned char *tbs, size_t tbs_len) {
  LogInfo("calling CustomDigestSign");
  EVP_PKEY_CTX *pctx = EVP_MD_CTX_pkey_ctx(ctx);
  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(pctx);
  if (!pkey) {
    fprintf(stderr, "Could not get EVP_PKEY.\n");
    return 0;
  }
  CustomKey *key = GetCustomKey(EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_pkey_ctx(ctx)));
  if (!key) {
    fprintf(stderr, "Could not get CustomKey from EVP_PKEY.\n");
    return 0;
  }
  if (EnableLogging) {
    std::cout << "tls_offload.cpp: " << "before calling key->Sign, " << "sig len: " << *sig_len << std::endl;
  }
  int res = key->sign_func_(sig, sig_len, tbs, tbs_len);
  if (EnableLogging) {
    std::cout << "tls_offload.cpp: " << "after calling key->Sign, " << "sig len: " << *sig_len 
      << "\nsignature: " << *sig << "\nkey->sign_func result: " << res << std::endl;
  }
  return res;  
}

OwnedEVP_PKEY_METHOD MakeCustomMethod(int nid) {
  OwnedEVP_PKEY_METHOD method(EVP_PKEY_meth_new(
      nid, EVP_PKEY_FLAG_SIGCTX_CUSTOM | EVP_PKEY_FLAG_AUTOARGLEN));
  if (!method) {
    return nullptr;
  }

  const EVP_PKEY_METHOD *ossl_method = EVP_PKEY_meth_find(nid);
  if (!ossl_method) {
    return nullptr;
  }
  int (*init)(EVP_PKEY_CTX *);
  EVP_PKEY_meth_get_init(ossl_method, &init);
  EVP_PKEY_meth_set_init(method.get(), init);
  void (*cleanup)(EVP_PKEY_CTX *);
  EVP_PKEY_meth_get_cleanup(ossl_method, &cleanup);
  EVP_PKEY_meth_set_cleanup(method.get(), cleanup);
  int (*ctrl)(EVP_PKEY_CTX *, int, int, void *);
  int (*ctrl_str)(EVP_PKEY_CTX *, const char *, const char *);
  EVP_PKEY_meth_get_ctrl(ossl_method, &ctrl, &ctrl_str);
  EVP_PKEY_meth_set_ctrl(method.get(), ctrl, ctrl_str);
 
  EVP_PKEY_meth_set_digestsign(method.get(), CustomDigestSign);
  return method;
}
 
static EVP_PKEY_METHOD *custom_rsa_pkey_method, *custom_ec_pkey_method;
static ENGINE *custom_engine = nullptr;

static int EngineGetMethods(ENGINE *e, EVP_PKEY_METHOD **out_method,
                            const int **out_nids, int nid) {
  if (!out_method) {
    static const int kNIDs[] = {EVP_PKEY_EC, EVP_PKEY_RSA};
    *out_nids = kNIDs;
    return sizeof(kNIDs) / sizeof(kNIDs[0]);
  }
 
  switch (nid) {
    case EVP_PKEY_EC:
      *out_method = custom_ec_pkey_method;
      return 1;
    case EVP_PKEY_RSA:
      *out_method = custom_rsa_pkey_method;
      return 1;
  }
  return 0;
}
 
static bool InitEngine() {
  custom_rsa_pkey_method = MakeCustomMethod(EVP_PKEY_RSA).release();
  custom_ec_pkey_method = MakeCustomMethod(EVP_PKEY_EC).release();
  if (!custom_rsa_pkey_method || !custom_ec_pkey_method) {
    return false;
  }
 
  OwnedENGINE engine(ENGINE_new());
  if (!engine ||
      !ENGINE_set_pkey_meths(engine.get(), EngineGetMethods)) {
    return false;
  }
  custom_engine = engine.release();
  return true;
}

OwnedEVP_PKEY MakeCustomKey(std::unique_ptr<CustomKey> custom_key, X509 *cert) {
  unsigned char *spki = nullptr;
  int spki_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &spki);
  if (spki_len < 0) {
    return nullptr;
  }
  OwnedOpenSSLBuffer owned_spki(spki);
  
  const unsigned char *ptr = spki;
  OwnedX509_PUBKEY pubkey(d2i_X509_PUBKEY(nullptr, &ptr, spki_len));
  if (!pubkey) {
    return nullptr;
  }
 
  OwnedEVP_PKEY wrapped(X509_PUBKEY_get(pubkey.get()));
  if (!wrapped ||
      !EVP_PKEY_set1_engine(wrapped.get(), custom_engine) ||
      !SetCustomKey(wrapped.get(), std::move(custom_key))) {
    return nullptr;
  }
  return wrapped;
}

static OwnedX509 CertFromPEM(const char *pem) {
  OwnedBIO bio(BIO_new_mem_buf(pem, strlen(pem)));
  if (!bio) {
    return nullptr;
  }
  return OwnedX509(
      PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}

static bool ServeTLS(SignFunc sign_func, const char *cert, SSL_CTX *ctx) {
  LogInfo("calling ServeTLS");

  LogInfo("create x509 using CertFromPEM");
  OwnedX509 x509 = CertFromPEM(cert);
  LogInfo("create custom key");
  OwnedEVP_PKEY wrapped_key = MakeCustomKey(
      std::make_unique<CustomKey>(sign_func), x509.get());
  if (!wrapped_key) {
    LogInfo("failed to create custom key");
    return false;
  }
  if (!SSL_CTX_use_PrivateKey(ctx, wrapped_key.get())) {
    LogInfo("SSL_CTX_use_PrivateKey failed");
    return false;
  }
  if (!SSL_CTX_use_certificate(ctx, x509.get())) {
    LogInfo("SSL_CTX_use_certificate failed");
    return false;
  }
  if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
    LogInfo("SSL_CTX_set_min_proto_version failed");
    return false;
  }
  return true;
}

}  // namespace

// Add `extern "C"` to avoid name mangling.
#ifdef _WIN32
extern "C" int __declspec(dllexport) OffloadSigning(SignFunc sign_func, const char *cert, SSL_CTX *ctx) {
#else
extern "C" int OffloadSigning(SignFunc sign_func, const char *cert, SSL_CTX *ctx) {
#endif
  char * val = getenv("GOOGLE_AUTH_TLS_OFFLOAD_LOGGING");
  EnableLogging = (val == nullptr)? false : true;
  LogInfo("entering offload function");
  if (!custom_engine) {
    LogInfo("initializing ex data and custom engine");
    if (!InitExData() || !InitEngine()) {
      ERR_print_errors_fp(stderr);
      return 0;
    }
  }
  if (!ServeTLS(sign_func, cert, ctx)) {
    ERR_print_errors_fp(stderr);
    return 0;
  }
  LogInfo("offload function is done");
  return 1;
}

#ifdef _WIN32
int Signer(unsigned char *sig, size_t *sig_len, const unsigned char *tbs, size_t tbs_len) {
  printf("calling sign\n");
  WindowsSigner signer;
  signer.is_rsa = false;
  signer.GetSignerCert();
  signer.GetPrivateKey();
  unsigned char *tbsCopy = new unsigned char(tbs_len);
  for (int i = 0; i < tbs_len; i++) tbsCopy[i] = tbs[i];
  signer.CreateHash(tbsCopy, tbs_len);
  delete tbsCopy;
  DWORD len;
  signer.NCryptSign(sig, &len);
  *sig_len = (size_t)len;
  return 1;
}
extern "C" int __declspec(dllexport) OffloadSigningWindowsSigner(const char *cert, SSL_CTX *ctx) {
  return OffloadSigning(&Signer, cert, ctx);
}

PyMODINIT_FUNC PyInit_tls_offload_ext(void) {
    Py_Initialize();
    return PyModule_Create(nullptr);
}
#endif