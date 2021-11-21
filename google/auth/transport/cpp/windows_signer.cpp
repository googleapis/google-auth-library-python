#include <iostream>
#include <Python.h>

#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

//-------------------------------------------------------------------
#define SIGNER_NAME L"localhost"

//-------------------------------------------------------------------
//    Define the name of the store where the needed certificate
//    can be found. 

#define CERT_STORE_NAME  L"MY"

//-------------------------------------------------------------------
//   Local function prototypes.
void MyHandleError(LPTSTR psz);
bool SignMessage(CRYPT_DATA_BLOB *pSignedMessageBlob);
bool VerifySignedMessage(
    CRYPT_DATA_BLOB *pSignedMessageBlob, 
    CRYPT_DATA_BLOB *pDecodedMessageBlob);

void _tmain()
{    
    CRYPT_DATA_BLOB SignedMessage;

    if(SignMessage(&SignedMessage))
    {
        CRYPT_DATA_BLOB DecodedMessage;

        if(VerifySignedMessage(&SignedMessage, &DecodedMessage))
        {
            free(DecodedMessage.pbData);
        }

        free(SignedMessage.pbData);
    }

    _tprintf(TEXT("Press any key to exit."));
    _getch();
}

//-------------------------------------------------------------------
//    MyHandleError
void MyHandleError(LPTSTR psz)
{
    _ftprintf(stderr, TEXT("An error occurred in the program. \n"));
    _ftprintf(stderr, TEXT("%s\n"), psz);
    _ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
    _ftprintf(stderr, TEXT("Program terminating. \n"));
} // End of MyHandleError

//-------------------------------------------------------------------
//    SignMessage
bool SignMessage(CRYPT_DATA_BLOB *pSignedMessageBlob)
{
    bool fReturn = false;
    BYTE* pbMessage;
    DWORD cbMessage;
    HCERTSTORE hCertStore = NULL;   
    PCCERT_CONTEXT pSignerCert; 
    CRYPT_SIGN_MESSAGE_PARA  SigParams = {};
    DWORD cbSignedMessageBlob;
    BYTE  *pbSignedMessageBlob = NULL;

    // Initialize the output pointer.
    pSignedMessageBlob->cbData = 0;
    pSignedMessageBlob->pbData = NULL;

    // The message to be signed.
    // Usually, the message exists somewhere and a pointer is
    // passed to the application.
    pbMessage = 
        (BYTE*)TEXT("CryptoAPI is a good way to handle security");

    // Calculate the size of message. To include the 
    // terminating null character, the length is one more byte 
    // than the length returned by the strlen function.
    cbMessage = (lstrlen((TCHAR*) pbMessage) + 1) * sizeof(TCHAR);

    // Create the MessageArray and the MessageSizeArray.
    const BYTE* MessageArray[] = {pbMessage};
    DWORD MessageSizeArray[1];
    MessageSizeArray[0] = cbMessage;

    //  Begin processing. 
    _tprintf(TEXT("The message to be signed is \"%s\".\n"),
        pbMessage);

    // Open the certificate store.
    if ( !( hCertStore = CertOpenStore(
       CERT_STORE_PROV_SYSTEM,
       0,
       NULL,
       CERT_SYSTEM_STORE_CURRENT_USER,
       CERT_STORE_NAME)))
    {
         MyHandleError(TEXT("The MY store could not be opened."));
         goto exit_SignMessage;
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
        MyHandleError( TEXT("Signer certificate not found."));
        goto exit_SignMessage;
    }
    
    printf("before calling crypt encode\n");
    CRYPT_RSA_SSA_PSS_PARAMETERS PssParam = {};
    PssParam.HashAlgorithm.pszObjId = szOID_NIST_sha256;
    DWORD cbEncoded;
    BYTE *pbEncoded;
    if(CryptEncodeObject(
        MY_ENCODING_TYPE,        // the encoding/decoding type
        szOID_RSA_SSA_PSS,    
        &PssParam,              
        NULL,
        &cbEncoded))    // fill in the length needed for
                        // the encoded buffer
    {
        printf("The number of bytes needed is %d \n",cbEncoded);
    }
    else
    {
        MyHandleError("The first call to the function failed.\n");
    }

    if(pbEncoded = (BYTE*)malloc(cbEncoded))
    {
        printf("Memory for pvEncoded has been allocated.\n");
    }
    else
    {
        MyHandleError("Memory allocation failed.");
    }

    if(CryptEncodeObject(
        MY_ENCODING_TYPE,
        szOID_RSA_SSA_PSS,    
        &PssParam,              
        pbEncoded,
        &cbEncoded))
    {
        printf("The encoding works\n");
        // LPSTR sz;
        // if(sz=(char *)malloc(512))
        // {
        //     printf("Memory for sz allocated\n");
        // }
        // else
        // {
        //     MyHandleError("Memory allocation failed.");
        // }
        // ByteToStr(cbEncoded, pbEncoded,sz);
        // printf("The Encoded octets are \n%s\n",sz);
    }
    else
    {
        MyHandleError("Encoding failed.");
    }

    // Initialize the signature structure.
    SigParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
    SigParams.dwMsgEncodingType = MY_ENCODING_TYPE;
    SigParams.pSigningCert = pSignerCert;
    SigParams.HashAlgorithm.pszObjId = szOID_RSA_SSA_PSS;
    SigParams.HashAlgorithm.Parameters.cbData = cbEncoded;
    SigParams.HashAlgorithm.Parameters.pbData = pbEncoded;
    SigParams.cMsgCert = 1;
    SigParams.rgpMsgCert = &pSignerCert;
    SigParams.cAuthAttr = 0;
    SigParams.dwInnerContentType = 0;
    SigParams.cMsgCrl = 0;
    SigParams.cUnauthAttr = 0;
    SigParams.dwFlags = 0;
    SigParams.pvHashAuxInfo = NULL;
    SigParams.rgAuthAttr = NULL;

    // First, get the size of the signed BLOB.
    if(CryptSignMessage(
        &SigParams,
        FALSE,
        1,
        MessageArray,
        MessageSizeArray,
        NULL,
        &cbSignedMessageBlob))
    {
        _tprintf(TEXT("%d bytes needed for the encoded BLOB.\n"),
            cbSignedMessageBlob);
    }
    else
    {
        MyHandleError(TEXT("Getting signed BLOB size failed"));
        goto exit_SignMessage;
    }

    // Allocate memory for the signed BLOB.
    if(!(pbSignedMessageBlob = 
       (BYTE*)malloc(cbSignedMessageBlob)))
    {
        MyHandleError(
            TEXT("Memory allocation error while signing."));
        goto exit_SignMessage;
    }

    // Get the signed message BLOB.
    if(CryptSignMessage(
          &SigParams,
          FALSE,
          1,
          MessageArray,
          MessageSizeArray,
          pbSignedMessageBlob,
          &cbSignedMessageBlob))
    {
        _tprintf(TEXT("The message was signed successfully. \n"));

        // pbSignedMessageBlob now contains the signed BLOB.
        fReturn = true;
    }
    else
    {
        MyHandleError(TEXT("Error getting signed BLOB"));
        goto exit_SignMessage;
    }

exit_SignMessage:

    // Clean up and free memory as needed.
    if(pSignerCert)
    {
        CertFreeCertificateContext(pSignerCert);
    }
    
    if(hCertStore)
    {
        CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
        hCertStore = NULL;
    }

    // Only free the signed message if a failure occurred.
    if(!fReturn)
    {
        if(pbSignedMessageBlob)
        {
            free(pbSignedMessageBlob);
            pbSignedMessageBlob = NULL;
        }
    }

    if(pbSignedMessageBlob)
    {
        pSignedMessageBlob->cbData = cbSignedMessageBlob;
        pSignedMessageBlob->pbData = pbSignedMessageBlob;
    }
    
    return fReturn;
}

//-------------------------------------------------------------------
//    VerifySignedMessage
//
//    Verify the message signature. Usually, this would be done in 
//    a separate program. 
bool VerifySignedMessage(
    CRYPT_DATA_BLOB *pSignedMessageBlob, 
    CRYPT_DATA_BLOB *pDecodedMessageBlob)
{
    bool fReturn = false;
    DWORD cbDecodedMessageBlob;
    BYTE *pbDecodedMessageBlob = NULL;
    CRYPT_VERIFY_MESSAGE_PARA VerifyParams;

    // Initialize the output.
    pDecodedMessageBlob->cbData = 0;
    pDecodedMessageBlob->pbData = NULL;

    // Initialize the VerifyParams data structure.
    VerifyParams.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    VerifyParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    VerifyParams.hCryptProv = 0;
    VerifyParams.pfnGetSignerCertificate = NULL;
    VerifyParams.pvGetArg = NULL;

    // First, call CryptVerifyMessageSignature to get the length 
    // of the buffer needed to hold the decoded message.
    if(CryptVerifyMessageSignature(
        &VerifyParams,
        0,
        pSignedMessageBlob->pbData,
        pSignedMessageBlob->cbData,
        NULL,
        &cbDecodedMessageBlob,
        NULL))
    {
        _tprintf(TEXT("%d bytes needed for the decoded message.\n"),
            cbDecodedMessageBlob);

    }
    else
    {
        _tprintf(TEXT("Verification message failed. \n"));
        goto exit_VerifySignedMessage;
    }

    //---------------------------------------------------------------
    //   Allocate memory for the decoded message.
    if(!(pbDecodedMessageBlob = 
       (BYTE*)malloc(cbDecodedMessageBlob)))
    {
        MyHandleError(
            TEXT("Memory allocation error allocating decode BLOB."));
        goto exit_VerifySignedMessage;
    }

    //---------------------------------------------------------------
    // Call CryptVerifyMessageSignature again to verify the signature
    // and, if successful, copy the decoded message into the buffer. 
    // This will validate the signature against the certificate in 
    // the local store.
    if(CryptVerifyMessageSignature(
        &VerifyParams,
        0,
        pSignedMessageBlob->pbData,
        pSignedMessageBlob->cbData,
        pbDecodedMessageBlob,
        &cbDecodedMessageBlob,
        NULL))
    {
        _tprintf(TEXT("The verified message is \"%s\".\n"),
            pbDecodedMessageBlob);

        fReturn = true;
    }
    else
    {
        _tprintf(TEXT("Verification message failed. \n"));
    }

exit_VerifySignedMessage:
    // If something failed and the decoded message buffer was 
    // allocated, free it.
    if(!fReturn)
    {
        if(pbDecodedMessageBlob)
        {
            free(pbDecodedMessageBlob);
            pbDecodedMessageBlob = NULL;
        }
    }

    // If the decoded message buffer is still around, it means the 
    // function was successful. Copy the pointer and size into the 
    // output parameter.
    if(pbDecodedMessageBlob)
    {
        pDecodedMessageBlob->cbData = cbDecodedMessageBlob;
        pDecodedMessageBlob->pbData = pbDecodedMessageBlob;
    }

    return fReturn;
}

//-------------------------------------------------------------------
// my code
// void store()
// {
//     //-------------------------------------------------------------------
//     // Declare and initialize variables.
//     HCERTSTORE  hSystemStore;              // The system store handle.
//     PCCERT_CONTEXT  pSignerCert = NULL;   // Set to NULL for the first 
//                                         // call to
//                                         // CertFindCertificateInStore.
//     LPCSTR lpszCertSubject = (LPCSTR) "localhost";


//     //-------------------------------------------------------------------
//     // Open the certificate store to be searched.
//     if(hSystemStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, 
//         //CERT_SYSTEM_STORE_CURRENT_USER,
//         CERT_SYSTEM_STORE_LOCAL_MACHINE,
//         L"MY")) {
//         printf("Opened the MY system store. \n");
//     } else {
//         printf( "Could not open the MY system store.\n");
//         exit(1);
//     }

//     //-------------------------------------------------------------------
//     // Get a certificate that has lpszCertSubject as its 
//     // subject. 
//     if(pSignerCert=CertFindCertificateInStore(hSystemStore, MY_ENCODING_TYPE, 0, 
//         CERT_FIND_SUBJECT_STR_A, lpszCertSubject, NULL)) {
//         printf("The desired certificate was found. \n");
//     } else {
//         printf("Could not find the desired certificate.\n");
//     }

//     //-------------------------------------------------------------------
//     // Signing
//     CRYPT_DATA_BLOB SignedMessage; 
//     SignedMessage.cbData = 0;
//     SignedMessage.pbData = NULL;
//     DWORD cbSignedMessageBlob;
//     BYTE  *pbSignedMessageBlob = NULL;

//     BYTE* pbMessage = (BYTE*)TEXT("foo"); // message to sign
//     DWORD cbMessage = (lstrlen((TCHAR*) pbMessage) + 1) * sizeof(TCHAR);
//     const BYTE* MessageArray[] = {pbMessage};
//     DWORD_PTR MessageSizeArray[1];
//     MessageSizeArray[0] = cbMessage;

//     CRYPT_SIGN_MESSAGE_PARA SigParams;
//     SigParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
//     SigParams.dwMsgEncodingType = MY_ENCODING_TYPE;
//     SigParams.pSigningCert = pSignerCert;
//     SigParams.HashAlgorithm.pszObjId = szOID_RSA_SHA1RSA; //szOID_RSA_SSA_PSS;
//     SigParams.HashAlgorithm.Parameters.cbData = NULL;
//     SigParams.cMsgCert = 1;
//     SigParams.rgpMsgCert = &pSignerCert;
//     SigParams.cAuthAttr = 0;
//     SigParams.dwInnerContentType = 0;
//     SigParams.cMsgCrl = 0;
//     SigParams.cUnauthAttr = 0;
//     SigParams.dwFlags = 0;
//     SigParams.pvHashAuxInfo = NULL;
//     SigParams.rgAuthAttr = NULL;

//     if(CryptSignMessage(
//         &SigParams,
//         FALSE,
//         1,
//         MessageArray,
//         MessageSizeArray,
//         NULL,
//         &cbSignedMessageBlob))
//     {
//         _tprintf(TEXT("%d bytes needed for the encoded BLOB.\n"),
//             cbSignedMessageBlob);
//     }
//     else
//     {
//         MyHandleError(TEXT("Getting signed BLOB size failed"));
//         goto exit_SignMessage;
//     }

//     if(!(pbSignedMessageBlob = 
//        (BYTE*)malloc(cbSignedMessageBlob)))
//     {
//         MyHandleError(
//             TEXT("Memory allocation error while signing."));
//         goto exit_SignMessage;
//     }

//     // Get the signed message BLOB.
//     if(CryptSignMessage(
//           &SigParams,
//           FALSE,
//           1,
//           MessageArray,
//           MessageSizeArray,
//           pbSignedMessageBlob,
//           &cbSignedMessageBlob))
//     {
//         _tprintf(TEXT("The message was signed successfully. \n"));
//     }
//     else
//     {
//         MyHandleError(TEXT("Error getting signed BLOB"));
//         goto exit_SignMessage;
//     }

//     //-------------------------------------------------------------------
//     // Clean up. 
//     exit_SignMessage:
//     if(pSignerCert) CertFreeCertificateContext(pSignerCert);
//     if(hSystemStore) CertCloseStore(hSystemStore, CERT_CLOSE_STORE_CHECK_FLAG);
// }

static PyObject* my(PyObject *self, PyObject *args) {

    printf("calling my\n");

    //store();
    _tmain();

    Py_INCREF(Py_None);
    return Py_None; 
}

/* This array lists all of the methods we are putting into our module. Take
note of the sentinel value at the end to indicate the ending of the array. */

static PyMethodDef Methods[] = {
    {"my", my, METH_VARARGS, "Print Hello World"},
    {NULL, NULL, 0, NULL} /* The sentinel value. */
};


/* This declares set-up information for our module.*/

static struct PyModuleDef module = {

    PyModuleDef_HEAD_INIT,
    "my",
    NULL, /*This is for documentation, which we won't use; so it is NULL. */
    -1,
    Methods
};

PyMODINIT_FUNC PyInit_windows_signer_ext(void) {

    return PyModule_Create(&module);
}