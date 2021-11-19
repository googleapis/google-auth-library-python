#include <iostream>
#include <Python.h>

#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define SIGNER_NAME L"localhost"
#define CERT_STORE_NAME  L"MY"

class WindowsSigner {
    public:
        WindowsSigner() {}
        ~WindowsSigner();
        void GetSignerCert();
        void Sign();
    private:
        void Cleanup();
        void HandleError(LPTSTR psz);
        CRYPT_SIGN_MESSAGE_PARA CreateSignPara();

        HCERTSTORE hCertStore = NULL;   
        PCCERT_CONTEXT pSignerCert = NULL; 
};

void WindowsSigner::Cleanup() {
    if(pSignerCert) CertFreeCertificateContext(pSignerCert);
    if(hCertStore) CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
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
       CERT_SYSTEM_STORE_CURRENT_USER,
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
    SigParams.HashAlgorithm.pszObjId = szOID_RSA_SHA1RSA;
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
        FALSE,
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
          FALSE,
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

static PyObject* sign(PyObject *self, PyObject *args) {
    printf("calling sign\n");
    WindowsSigner signer;
    signer.GetSignerCert();
    signer.Sign();
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