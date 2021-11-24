#include <Windows.h>
#include <wincrypt.h>

#include "tls_offload.h"

class WinCertStoreKey : public CustomKey {
    public:
        WinCertStoreKey() : CustomKey(NULL) {}
        ~WinCertStoreKey();
        void GetSignerCert();
        void GetPrivateKey();
        void CreateHash(PBYTE pbToSign, DWORD cbToSign);
        void NCryptSign(PBYTE pbSignatureOut, PDWORD cbSignatureOut);
        bool Sign(unsigned char *sig, size_t *sig_len, const unsigned char *tbs, size_t tbs_len) override;
        bool is_rsa;
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
};