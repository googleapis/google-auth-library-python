#include <string>
#include <Windows.h>
#include <wincrypt.h>

#include "tls_offload.h"

class WinCertStoreKey : public CustomKey {
    public:
        WinCertStoreKey(bool is_rsa, bool local_machine_store, const char *store_name, const char *subject) : CustomKey(NULL) {
            is_rsa_type = is_rsa;
            cert_store_provider = local_machine_store ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER;
            cert_store_name = std::string(store_name);
            cert_subject = std::string(subject);
        }
        ~WinCertStoreKey();
        void GetSignerCert();
        void GetPrivateKey();
        void CreateHash(PBYTE pbToSign, DWORD cbToSign);
        void NCryptSign(PBYTE pbSignatureOut, PDWORD cbSignatureOut);
        bool Sign(unsigned char *sig, size_t *sig_len, const unsigned char *tbs, size_t tbs_len) override;
    private:
        void Cleanup();
        void HandleError(LPTSTR psz);
        CRYPT_SIGN_MESSAGE_PARA CreateSignPara();

        // cert store / cert
        HCERTSTORE hCertStore = NULL;   
        PCCERT_CONTEXT pSignerCert = NULL;
        // private key
        HCRYPTPROV hCryptProv = NULL;
        DWORD dwKeySpec;
        // hash
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        PBYTE pbHashObject = NULL;
        PBYTE pbHash = NULL;
        DWORD cbHash = 0;

        bool is_rsa_type;
        DWORD cert_store_provider;
        std::string cert_store_name;
        std::string cert_subject;
};