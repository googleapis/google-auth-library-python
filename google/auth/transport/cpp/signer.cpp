#include <iostream>
#include <Python.h>

// #include <Windows.h>
// #include <wincrypt.h>
#include "signer.h"
#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#include <bcrypt.h>
#include <ncrypt.h>

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define SIGNER_NAME L"localhost"
#define CERT_STORE_NAME  L"MY"
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

// class WindowsSigner {
//     public:
//         WindowsSigner() {}
//         ~WindowsSigner();
//         void GetSignerCert();
//         void Sign();
//         void GetPrivateKey();
//         void CreateHash();
//         void NCryptSign();
//     private:
//         void Cleanup();
//         void HandleError(LPTSTR psz);
//         CRYPT_SIGN_MESSAGE_PARA CreateSignPara();

//         // cert store / cert
//         HCERTSTORE hCertStore = NULL;   
//         PCCERT_CONTEXT pSignerCert = NULL;
//         // private key
//         HCRYPTPROV hCryptProv = NULL;
//         DWORD dwKeySpec;
//         // hash
//         BCRYPT_ALG_HANDLE hAlg = NULL;
//         BCRYPT_HASH_HANDLE hHash = NULL;
//         PBYTE pbHashObject = NULL;
//         PBYTE pbHash = NULL;
//         DWORD cbHash = 0;
// };

void WindowsSigner::Cleanup() {
    if(pSignerCert) CertFreeCertificateContext(pSignerCert);
    if(hCertStore) CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    if(hAlg) BCryptCloseAlgorithmProvider(hAlg,0);
    if (hHash) BCryptDestroyHash(hHash);
    if(pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
    if(pbHash) HeapFree(GetProcessHeap(), 0, pbHash);
}

WindowsSigner::~WindowsSigner() {
    Cleanup();
}

void WindowsSigner::HandleError(LPTSTR psz) {
    _ftprintf(stderr, TEXT("An error occurred in the program. \n"));
    _ftprintf(stderr, TEXT("%s\n"), psz);
    _ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
    Cleanup();
}

void WindowsSigner::GetSignerCert() {
    if (!(hCertStore = CertOpenStore(
       CERT_STORE_PROV_SYSTEM,
       0,
       NULL,
       CERT_SYSTEM_STORE_LOCAL_MACHINE,
       //CERT_SYSTEM_STORE_CURRENT_USER,
       CERT_STORE_NAME)))
    {
        HandleError(TEXT("The MY store could not be opened."));
        return;
    }

    // Get a pointer to the signer's certificate.
    // This certificate must have access to the signer's private key.
    if(pSignerCert = CertFindCertificateInStore(
       hCertStore,
       MY_ENCODING_TYPE,
       0,
       CERT_FIND_SUBJECT_STR,
       SIGNER_NAME,
       NULL))
    {
       _tprintf(TEXT("The signer's certificate was found.\n"));
    }
    else
    {
        HandleError( TEXT("Signer certificate not found."));
        return;
    }
}

CRYPT_SIGN_MESSAGE_PARA WindowsSigner::CreateSignPara() {
    CRYPT_SIGN_MESSAGE_PARA SigParams = {};
    SigParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
    SigParams.dwMsgEncodingType = MY_ENCODING_TYPE;
    SigParams.pSigningCert = pSignerCert;
    //SigParams.HashAlgorithm.pszObjId = szOID_RSA_SHA1RSA;
    SigParams.HashAlgorithm.pszObjId = szOID_ECDSA_SHA256;
    SigParams.cMsgCert = 1;
    SigParams.rgpMsgCert = &pSignerCert;
    SigParams.cAuthAttr = 0;
    SigParams.dwInnerContentType = 0;
    SigParams.cMsgCrl = 0;
    SigParams.cUnauthAttr = 0;
    SigParams.dwFlags = 0;
    SigParams.pvHashAuxInfo = NULL;
    SigParams.rgAuthAttr = NULL;
    return SigParams;
}

void WindowsSigner::Sign() {
    // Calculate the size of the message to sign, and make arrays
    // for the message and message size.
    BYTE *pbMessage = (BYTE*)TEXT("The message to sign");
    DWORD cbMessage = (lstrlen((TCHAR*) pbMessage) + 1) * sizeof(TCHAR);
    const BYTE* MessageArray[] = {pbMessage};
    DWORD MessageSizeArray[1];
    MessageSizeArray[0] = cbMessage;
    _tprintf(TEXT("The message to be signed is \"%s\".\n"), pbMessage);

    CRYPT_SIGN_MESSAGE_PARA SigParams = CreateSignPara();

    // We need to call CryptSignMessage twice. First time set pcSignedBlob parameter
    // to NULL to calculate the signed Blob size; then allocate the memory the signed
    // Blob and do the actual signing.
    // First, get the size of the signed BLOB.
    DWORD cbSignedMessageBlob;
    if(CryptSignMessage(
        &SigParams,
        TRUE,
        1,
        MessageArray,
        MessageSizeArray,
        NULL,
        &cbSignedMessageBlob)) {
        _tprintf(TEXT("%d bytes needed for the encoded BLOB.\n"), cbSignedMessageBlob);
    } else {
        HandleError(TEXT("Getting signed BLOB size failed"));
        return;
    }

    // Allocate memory for the signed BLOB.
    BYTE *pbSignedMessageBlob = NULL;
    if(!(pbSignedMessageBlob = (BYTE*)malloc(cbSignedMessageBlob))) {
        HandleError(TEXT("Memory allocation error while signing."));
        return;
    }

    // Get the signed message BLOB.
    if(CryptSignMessage(
          &SigParams,
          TRUE,
          1,
          MessageArray,
          MessageSizeArray,
          pbSignedMessageBlob,
          &cbSignedMessageBlob)) {
        // pbSignedMessageBlob now contains the signed BLOB.
        _tprintf(TEXT("The message was signed successfully. \n"));
    } else {
        HandleError(TEXT("Error getting signed BLOB"));
        free(pbSignedMessageBlob);
    }
}

void WindowsSigner::GetPrivateKey() {
    if(!(CryptAcquireCertificatePrivateKey(
        pSignerCert,
        CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
        NULL,
        &hCryptProv,
        &dwKeySpec,
        NULL)))
    {
        HandleError(TEXT("CryptAcquireCertificatePrivateKey.\n"));
    } else {
        printf("Get private key\n");
    }
}

void WindowsSigner::CreateHash(PBYTE pbToSign, DWORD cbToSign) {
    NTSTATUS                status          = STATUS_UNSUCCESSFUL;
    DWORD                   cbData          = 0,
                            cbHashObject    = 0;

    //open an algorithm handle
    if(!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    //calculate the size of the buffer to hold the hash object
    if(!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash object on the heap
    pbHashObject = (PBYTE)HeapAlloc (GetProcessHeap(), 0, cbHashObject);
    if(NULL == pbHashObject)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

   //calculate the length of the hash
    if(!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash buffer on the heap
    pbHash = (PBYTE)HeapAlloc (GetProcessHeap(), 0, cbHash);
    if(NULL == pbHash)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //create a hash
    if(!NT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
        goto Cleanup;
    }
    

    //hash some data
    if(!NT_SUCCESS(status = BCryptHashData(hHash, pbToSign, cbToSign, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
        goto Cleanup;
    }
    
    //close the hash
    if(!NT_SUCCESS(status = BCryptFinishHash(hHash, pbHash, cbHash, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
        goto Cleanup;
    }

    printf("Hash size is: %lu\n", cbHash);
    printf("Success!\n");

Cleanup:
    return;
}

void WindowsSigner::NCryptSign(PBYTE pbSignatureOut, PDWORD cbSignatureOut) {
    BCRYPT_ALG_HANDLE hSignAlg = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if(!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hSignAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL,0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }
    
    //sign the hash
    DWORD cbSignature = 0;
    SECURITY_STATUS secStatus = ERROR_SUCCESS;
    if(FAILED(secStatus = NCryptSignHash(hCryptProv,NULL,pbHash,cbHash,NULL, 0,&cbSignature,0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptSignHash\n", secStatus);
        goto Cleanup;
    } else {
        printf("First call to NCryptSignHash succeeded, sig len %lu\n", cbSignature);
    }

    //allocate the signature buffer
    PBYTE pbSignature = NULL;
    pbSignature = (PBYTE)HeapAlloc(GetProcessHeap (), 0, cbSignature);
    if(NULL == pbSignature)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    if(FAILED(secStatus = NCryptSignHash(hCryptProv,NULL,pbHash,cbHash,pbSignature,cbSignature,&cbSignature,0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptSignHash\n", secStatus);
        goto Cleanup;
    } else {
        printf("Sign succeeded!\n");
        printf("Signature length is: %lu\n", cbSignature);
        if (pbSignatureOut && cbSignatureOut) {
            //int sig_size = (int)cbSignature;
            for (int i = 0; i < cbSignature; i++) {
                pbSignatureOut[i] = pbSignature[i];
            }
            *cbSignatureOut = cbSignature;
        }
    }

    Cleanup:
        return;
}

static PyObject* sign(PyObject *self, PyObject *args) {
    printf("calling sign\n");
    WindowsSigner signer;
    signer.GetSignerCert();
    signer.GetPrivateKey();
    static const BYTE rgbMsg[] = {0x61, 0x62, 0x63};
    signer.CreateHash((PBYTE)rgbMsg, sizeof(rgbMsg));
    signer.NCryptSign(NULL, NULL);
    Py_INCREF(Py_None);
    return Py_None; 
}

static PyMethodDef Methods[] = {
    {"sign", sign, METH_VARARGS, "The signer function"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "windows signer", NULL, -1, Methods};

PyMODINIT_FUNC PyInit_windows_signer_ext(void) {
    return PyModule_Create(&module);
}