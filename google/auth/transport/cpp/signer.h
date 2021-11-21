#include <Windows.h>
#include <wincrypt.h>

class WindowsSigner {
    public:
        //WindowsSigner() {}
        ~WindowsSigner();
        void GetSignerCert();
        void Sign();
        void GetPrivateKey();
        void CreateHash(PBYTE pbToSign, DWORD cbToSign);
        void NCryptSign(PBYTE pbSignatureOut, PDWORD cbSignatureOut);
    private:
        void Cleanup();
        void HandleError(LPTSTR psz);
        CRYPT_SIGN_MESSAGE_PARA CreateSignPara();

        bool is_rsa = true;

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