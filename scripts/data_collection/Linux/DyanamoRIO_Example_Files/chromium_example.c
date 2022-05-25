
#include "dr_api.h"
#include "utils.h"
#include "drwrap.h"
#include "drmgr.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* OpenSSL and GnuTLS - shared wrappers */
static void
wrap_cipher_create(void *wrapcxt, void **user_data);
static void
wrap_set_key(void *wrapcxt, void **user_data);
static void
wrap_AES_encrypt(void *wrapcxt, void **user_data);
static void
wrap_AES_decrypt(void *wrapcxt, void **user_data);
static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded);
static void
wrap_microphone_read(void *wrapcxt,  void **user_data);
static void
wrap_pa_mic(void *wrapcxt,  void **user_data);
static void
wrap_ssl_decode_auth_key(void *wrapcxt,  void **user_data);
static void
wrap_ssl_privkey(void *wrapcxt,  void **user_data);
static void
wrap_printf(void *wrapcxt,  void **user_data);
static void
wrap_preferred_cipher(void *wrapcxt,  void **user_data);
static void wrap__ZN3net9x509_util18CreateCryptoBufferERKN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZNK4GURL21SchemeIsCryptographicEv(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto4HMACC1ENS0_13HashAlgorithmE(void *wrapcxt,  void **user_data);
static void wrap__ZNK6crypto4HMAC12DigestLengthEv(void *wrapcxt,  void **user_data);
static void wrap__ZNK6crypto4HMAC4SignEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPhm(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto4HMACD1Ev(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto4HMAC4InitEPKhm(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto12SymmetricKey6ImportENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto9Encryptor4InitEPKNS_12SymmetricKeyENS0_4ModeEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto9EncryptorC1Ev(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto9Encryptor10SetCounterEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto9Encryptor7EncryptEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto9Encryptor7DecryptEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto9EncryptorD1Ev(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto10SecureHash6CreateENS0_9AlgorithmE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto16SHA256HashStringEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZNK6crypto13RSAPrivateKey15ExportPublicKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto13RSAPrivateKey24CreateFromPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto13RSAPrivateKey6CreateEt(void *wrapcxt,  void **user_data);
static void wrap__ZNK6crypto13RSAPrivateKey16ExportPrivateKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto13RSAPrivateKeyD1Ev(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto17SignatureVerifierC1Ev(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto17SignatureVerifier10VerifyInitENS0_18SignatureAlgorithmEN4base4spanIKhLm18446744073709551615EEES5_(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto17SignatureVerifier12VerifyUpdateEN4base4spanIKhLm18446744073709551615EEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto17SignatureVerifier11VerifyFinalEv(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto17SignatureVerifierD1Ev(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto16SHA256HashStringEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPvm(void *wrapcxt,  void **user_data);
static void wrap_CRYPTO_BUFFER_data(void *wrapcxt,  void **user_data);
static void wrap_CRYPTO_BUFFER_len(void *wrapcxt,  void **user_data);
static void wrap__ZNK6crypto4HMAC6VerifyEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_(void *wrapcxt,  void **user_data);
static void wrap__ZN8switches23kEnableWebRtcSrtpAesGcmE(void *wrapcxt,  void **user_data);
static void wrap__ZN8features24kImpulseScrollAnimationsE(void *wrapcxt,  void **user_data);
static void wrap__ZN3net18ClientCertStoreNSSC1ERKN4base17RepeatingCallbackIFPN6crypto36CryptoModuleBlockingPasswordDelegateERKNS_12HostPortPairEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto9RandBytesEPvm(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto12ECPrivateKey6CreateEv(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto12ECPrivateKey24CreateFromPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE(void *wrapcxt,  void **user_data);
static void wrap__ZNK6crypto12ECPrivateKey16ExportPrivateKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto12ECPrivateKeyD1Ev(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto18ECSignatureCreator6CreateEPNS_12ECPrivateKeyE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto9RandBytesEN4base4spanIhLm18446744073709551615EEE(void *wrapcxt,  void **user_data);
static void wrap__ZNK6crypto12ECPrivateKey18ExportRawPublicKeyEPNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZNK6crypto12ECPrivateKey15ExportPublicKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto14SecureMemEqualEPKvS1_m(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto4AeadC1ENS0_13AeadAlgorithmE(void *wrapcxt,  void **user_data);
static void wrap__ZNK6crypto4Aead9KeyLengthEv(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto4Aead4InitEPKNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZNK6crypto4Aead11NonceLengthEv(void *wrapcxt,  void **user_data);
static void wrap__ZNK6crypto4Aead4SealEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_S6_PNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto4AeadD1Ev(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto10HkdfSha256EN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES5_S5_m(void *wrapcxt,  void **user_data);
static void wrap__ZNK6crypto4Aead4OpenEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_S6_PNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto12SymmetricKey32DeriveKeyFromPasswordUsingPbkdf2ENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEESA_mm(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto12SymmetricKey32DeriveKeyFromPasswordUsingScryptENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEESA_mmmmm(void *wrapcxt,  void **user_data);
static void wrap__ZN3gcm12GCMStoreImplC1ERKN4base8FilePathEb13scoped_refptrINS1_19SequencedTaskRunnerEENSt4__Cr10unique_ptrINS_9EncryptorENS8_14default_deleteISA_EEEE(void *wrapcxt,  void **user_data);
static void wrap__ZNK6crypto12ECPrivateKey4CopyEv(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto12ECPrivateKey33CreateFromEncryptedPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto10HkdfSha256EN4base4spanIKhLm18446744073709551615EEES3_S3_m(void *wrapcxt,  void **user_data);
static void wrap__ZNK6crypto4HMAC4SignEN4base4spanIKhLm18446744073709551615EEENS2_IhLm18446744073709551615EEE(void *wrapcxt,  void **user_data);
static void wrap__ZNK6crypto4HMAC6VerifyEN4base4spanIKhLm18446744073709551615EEES4_(void *wrapcxt,  void **user_data);
static void wrap__ZN3net15X509Certificate12IsSelfSignedEPK16crypto_buffer_st(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto16SignatureCreator6CreateEPNS_13RSAPrivateKeyENS0_13HashAlgorithmE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto16SignatureCreator6UpdateEPKhi(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto16SignatureCreator5FinalEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto16SignatureCreatorD1Ev(void *wrapcxt,  void **user_data);
static void wrap__ZN3net9x509_util25CryptoBufferAsStringPieceEPK16crypto_buffer_st(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto16SignatureCreator4SignEPNS_13RSAPrivateKeyENS0_13HashAlgorithmEPKhiPNSt4__Cr6vectorIhNS6_9allocatorIhEEEE(void *wrapcxt,  void **user_data);
static void wrap__ZNK6crypto13RSAPrivateKey4CopyEv(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto4Aead4InitEN4base4spanIKhLm18446744073709551615EEE(void *wrapcxt,  void **user_data);
static void wrap__ZN3net9x509_util26CreateKeyAndSelfSignedCertERKNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEjN4base4TimeESB_PNS1_10unique_ptrIN6crypto13RSAPrivateKeyENS1_14default_deleteISE_EEEEPS7_(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto29DecodeSubjectPublicKeyInfoNSSEN4base4spanIKhLm18446744073709551615EEE(void *wrapcxt,  void **user_data);
static void wrap__ZN6crypto13EnsureNSSInitEv(void *wrapcxt,  void **user_data);
static void wrap__ZN3net15NSSCertDatabaseC1ENSt4__Cr10unique_ptrI15PK11SlotInfoStrN6crypto12NSSDestroyerIS3_XadL_Z13PK11_FreeSlotEEEEEES7_(void *wrapcxt,  void **user_data);
static void wrap__ZNK5media19KeySystemProperties15UseAesDecryptorEv(void *wrapcxt,  void **user_data);



static void *max_lock; 


static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
    app_pc towrap = (app_pc)dr_get_proc_address(mod->handle, "crypto_alloc_cipher");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap_cipher_create, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn’t wrap cipher_create\n");
            DR_ASSERT(ok);
        }
        printf("alloc_cipher = %x\n",towrap);
    }

    towrap = (app_pc)dr_get_proc_address(mod->handle, "crypto_cipher_setkey");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap_set_key, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn’t wrap set_key\n");
            DR_ASSERT(ok);
        }
        printf("set_key = %x\n",towrap);
    }

    towrap = (app_pc)dr_get_proc_address(mod->handle, "crypto_cipher_encrypt_one");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap_AES_encrypt, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn’t wrap encryption\n");
            DR_ASSERT(ok);
        }
        printf("encrypt = %x\n",towrap);
    }

    towrap = (app_pc)dr_get_proc_address(mod->handle, "crypto_cipher_decrypt_one");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap_AES_decrypt, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn’t wrap decrypt\n");
            DR_ASSERT(ok);
        }
        printf("decrypt = %x\n",towrap);
    }

    towrap = (app_pc)dr_get_proc_address(mod->handle, "snd_pcm_readi");

    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap_microphone_read, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn’t wrap mic\n");
            DR_ASSERT(ok);
        }
        printf("ALSA mic = %x\n",towrap);
    }

    towrap = (app_pc)dr_get_proc_address(mod->handle, "pa_stream_drain");

    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap_pa_mic, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn’t wrap mic\n");
            DR_ASSERT(ok);
        }
        printf("PA  = %x\n",towrap);
    }

    towrap = (app_pc)dr_get_proc_address(mod->handle, "SECKEY_DestroyPrivateKey");

    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap_ssl_privkey, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn’t wrap mic\n");
            DR_ASSERT(ok);
        }
        printf("PrivateKey = %x\n",towrap);
    }

    towrap = (app_pc)dr_get_proc_address(mod->handle, "CERT_DecodeAuthKeyID");

    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap_ssl_decode_auth_key, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn’t wrap mic\n");
            DR_ASSERT(ok);
        }
        printf("CERT Auth Key ID = %x\n",towrap);
    }

    towrap = (app_pc)dr_get_proc_address(mod->handle, "printf");

    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap_printf, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn’t wrap mic\n");
            DR_ASSERT(ok);
        }
        printf("printf = %x\n",towrap);
    }

    towrap = (app_pc)dr_get_proc_address(mod->handle, "SEC_ASN1DecodeItem");

    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap_preferred_cipher, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get SEC_ASN1DecodeItem\n");
            
        }

        printf("SEC_ASN1DecodeItem = %x\n",towrap);
    }

     
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN3net9x509_util18CreateCryptoBufferERKN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN3net9x509_util18CreateCryptoBufferERKN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN3net9x509_util18CreateCryptoBufferERKN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK4GURL21SchemeIsCryptographicEv");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK4GURL21SchemeIsCryptographicEv, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK4GURL21SchemeIsCryptographicEv\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto4HMACC1ENS0_13HashAlgorithmE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto4HMACC1ENS0_13HashAlgorithmE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto4HMACC1ENS0_13HashAlgorithmE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK6crypto4HMAC12DigestLengthEv");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK6crypto4HMAC12DigestLengthEv, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK6crypto4HMAC12DigestLengthEv\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK6crypto4HMAC4SignEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPhm");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK6crypto4HMAC4SignEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPhm, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK6crypto4HMAC4SignEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPhm\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto4HMACD1Ev");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto4HMACD1Ev, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto4HMACD1Ev\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto4HMAC4InitEPKhm");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto4HMAC4InitEPKhm, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto4HMAC4InitEPKhm\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto12SymmetricKey6ImportENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto12SymmetricKey6ImportENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto12SymmetricKey6ImportENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto9Encryptor4InitEPKNS_12SymmetricKeyENS0_4ModeEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto9Encryptor4InitEPKNS_12SymmetricKeyENS0_4ModeEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto9Encryptor4InitEPKNS_12SymmetricKeyENS0_4ModeEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto9EncryptorC1Ev");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto9EncryptorC1Ev, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto9EncryptorC1Ev\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto9Encryptor10SetCounterEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto9Encryptor10SetCounterEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto9Encryptor10SetCounterEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto9Encryptor7EncryptEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto9Encryptor7EncryptEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto9Encryptor7EncryptEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto9Encryptor7DecryptEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto9Encryptor7DecryptEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto9Encryptor7DecryptEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto9EncryptorD1Ev");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto9EncryptorD1Ev, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto9EncryptorD1Ev\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto10SecureHash6CreateENS0_9AlgorithmE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto10SecureHash6CreateENS0_9AlgorithmE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto10SecureHash6CreateENS0_9AlgorithmE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto16SHA256HashStringEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto16SHA256HashStringEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto16SHA256HashStringEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK6crypto13RSAPrivateKey15ExportPublicKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK6crypto13RSAPrivateKey15ExportPublicKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK6crypto13RSAPrivateKey15ExportPublicKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto13RSAPrivateKey24CreateFromPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto13RSAPrivateKey24CreateFromPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto13RSAPrivateKey24CreateFromPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto13RSAPrivateKey6CreateEt");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto13RSAPrivateKey6CreateEt, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto13RSAPrivateKey6CreateEt\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK6crypto13RSAPrivateKey16ExportPrivateKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK6crypto13RSAPrivateKey16ExportPrivateKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK6crypto13RSAPrivateKey16ExportPrivateKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto13RSAPrivateKeyD1Ev");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto13RSAPrivateKeyD1Ev, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto13RSAPrivateKeyD1Ev\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto17SignatureVerifierC1Ev");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto17SignatureVerifierC1Ev, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto17SignatureVerifierC1Ev\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto17SignatureVerifier10VerifyInitENS0_18SignatureAlgorithmEN4base4spanIKhLm18446744073709551615EEES5_");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto17SignatureVerifier10VerifyInitENS0_18SignatureAlgorithmEN4base4spanIKhLm18446744073709551615EEES5_, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto17SignatureVerifier10VerifyInitENS0_18SignatureAlgorithmEN4base4spanIKhLm18446744073709551615EEES5_\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto17SignatureVerifier12VerifyUpdateEN4base4spanIKhLm18446744073709551615EEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto17SignatureVerifier12VerifyUpdateEN4base4spanIKhLm18446744073709551615EEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto17SignatureVerifier12VerifyUpdateEN4base4spanIKhLm18446744073709551615EEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto17SignatureVerifier11VerifyFinalEv");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto17SignatureVerifier11VerifyFinalEv, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto17SignatureVerifier11VerifyFinalEv\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto17SignatureVerifierD1Ev");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto17SignatureVerifierD1Ev, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto17SignatureVerifierD1Ev\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto16SHA256HashStringEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPvm");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto16SHA256HashStringEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPvm, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto16SHA256HashStringEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPvm\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "CRYPTO_BUFFER_data");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap_CRYPTO_BUFFER_data, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get CRYPTO_BUFFER_data\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "CRYPTO_BUFFER_len");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap_CRYPTO_BUFFER_len, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get CRYPTO_BUFFER_len\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK6crypto4HMAC6VerifyEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK6crypto4HMAC6VerifyEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK6crypto4HMAC6VerifyEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN8switches23kEnableWebRtcSrtpAesGcmE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN8switches23kEnableWebRtcSrtpAesGcmE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN8switches23kEnableWebRtcSrtpAesGcmE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN8features24kImpulseScrollAnimationsE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN8features24kImpulseScrollAnimationsE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN8features24kImpulseScrollAnimationsE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN3net18ClientCertStoreNSSC1ERKN4base17RepeatingCallbackIFPN6crypto36CryptoModuleBlockingPasswordDelegateERKNS_12HostPortPairEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN3net18ClientCertStoreNSSC1ERKN4base17RepeatingCallbackIFPN6crypto36CryptoModuleBlockingPasswordDelegateERKNS_12HostPortPairEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN3net18ClientCertStoreNSSC1ERKN4base17RepeatingCallbackIFPN6crypto36CryptoModuleBlockingPasswordDelegateERKNS_12HostPortPairEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto9RandBytesEPvm");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto9RandBytesEPvm, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto9RandBytesEPvm\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto12ECPrivateKey6CreateEv");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto12ECPrivateKey6CreateEv, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto12ECPrivateKey6CreateEv\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto12ECPrivateKey24CreateFromPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto12ECPrivateKey24CreateFromPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto12ECPrivateKey24CreateFromPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK6crypto12ECPrivateKey16ExportPrivateKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK6crypto12ECPrivateKey16ExportPrivateKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK6crypto12ECPrivateKey16ExportPrivateKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto12ECPrivateKeyD1Ev");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto12ECPrivateKeyD1Ev, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto12ECPrivateKeyD1Ev\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto18ECSignatureCreator6CreateEPNS_12ECPrivateKeyE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto18ECSignatureCreator6CreateEPNS_12ECPrivateKeyE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto18ECSignatureCreator6CreateEPNS_12ECPrivateKeyE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto9RandBytesEN4base4spanIhLm18446744073709551615EEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto9RandBytesEN4base4spanIhLm18446744073709551615EEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto9RandBytesEN4base4spanIhLm18446744073709551615EEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK6crypto12ECPrivateKey18ExportRawPublicKeyEPNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK6crypto12ECPrivateKey18ExportRawPublicKeyEPNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK6crypto12ECPrivateKey18ExportRawPublicKeyEPNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK6crypto12ECPrivateKey15ExportPublicKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK6crypto12ECPrivateKey15ExportPublicKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK6crypto12ECPrivateKey15ExportPublicKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto14SecureMemEqualEPKvS1_m");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto14SecureMemEqualEPKvS1_m, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto14SecureMemEqualEPKvS1_m\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto4AeadC1ENS0_13AeadAlgorithmE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto4AeadC1ENS0_13AeadAlgorithmE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto4AeadC1ENS0_13AeadAlgorithmE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK6crypto4Aead9KeyLengthEv");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK6crypto4Aead9KeyLengthEv, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK6crypto4Aead9KeyLengthEv\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto4Aead4InitEPKNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto4Aead4InitEPKNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto4Aead4InitEPKNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK6crypto4Aead11NonceLengthEv");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK6crypto4Aead11NonceLengthEv, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK6crypto4Aead11NonceLengthEv\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK6crypto4Aead4SealEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_S6_PNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK6crypto4Aead4SealEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_S6_PNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK6crypto4Aead4SealEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_S6_PNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto4AeadD1Ev");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto4AeadD1Ev, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto4AeadD1Ev\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto10HkdfSha256EN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES5_S5_m");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto10HkdfSha256EN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES5_S5_m, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto10HkdfSha256EN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES5_S5_m\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK6crypto4Aead4OpenEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_S6_PNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK6crypto4Aead4OpenEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_S6_PNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK6crypto4Aead4OpenEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_S6_PNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto12SymmetricKey32DeriveKeyFromPasswordUsingPbkdf2ENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEESA_mm");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto12SymmetricKey32DeriveKeyFromPasswordUsingPbkdf2ENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEESA_mm, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto12SymmetricKey32DeriveKeyFromPasswordUsingPbkdf2ENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEESA_mm\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto12SymmetricKey32DeriveKeyFromPasswordUsingScryptENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEESA_mmmmm");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto12SymmetricKey32DeriveKeyFromPasswordUsingScryptENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEESA_mmmmm, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto12SymmetricKey32DeriveKeyFromPasswordUsingScryptENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEESA_mmmmm\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN3gcm12GCMStoreImplC1ERKN4base8FilePathEb13scoped_refptrINS1_19SequencedTaskRunnerEENSt4__Cr10unique_ptrINS_9EncryptorENS8_14default_deleteISA_EEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN3gcm12GCMStoreImplC1ERKN4base8FilePathEb13scoped_refptrINS1_19SequencedTaskRunnerEENSt4__Cr10unique_ptrINS_9EncryptorENS8_14default_deleteISA_EEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN3gcm12GCMStoreImplC1ERKN4base8FilePathEb13scoped_refptrINS1_19SequencedTaskRunnerEENSt4__Cr10unique_ptrINS_9EncryptorENS8_14default_deleteISA_EEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK6crypto12ECPrivateKey4CopyEv");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK6crypto12ECPrivateKey4CopyEv, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK6crypto12ECPrivateKey4CopyEv\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto12ECPrivateKey33CreateFromEncryptedPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto12ECPrivateKey33CreateFromEncryptedPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto12ECPrivateKey33CreateFromEncryptedPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto10HkdfSha256EN4base4spanIKhLm18446744073709551615EEES3_S3_m");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto10HkdfSha256EN4base4spanIKhLm18446744073709551615EEES3_S3_m, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto10HkdfSha256EN4base4spanIKhLm18446744073709551615EEES3_S3_m\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK6crypto4HMAC4SignEN4base4spanIKhLm18446744073709551615EEENS2_IhLm18446744073709551615EEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK6crypto4HMAC4SignEN4base4spanIKhLm18446744073709551615EEENS2_IhLm18446744073709551615EEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK6crypto4HMAC4SignEN4base4spanIKhLm18446744073709551615EEENS2_IhLm18446744073709551615EEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK6crypto4HMAC6VerifyEN4base4spanIKhLm18446744073709551615EEES4_");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK6crypto4HMAC6VerifyEN4base4spanIKhLm18446744073709551615EEES4_, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK6crypto4HMAC6VerifyEN4base4spanIKhLm18446744073709551615EEES4_\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN3net15X509Certificate12IsSelfSignedEPK16crypto_buffer_st");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN3net15X509Certificate12IsSelfSignedEPK16crypto_buffer_st, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN3net15X509Certificate12IsSelfSignedEPK16crypto_buffer_st\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto16SignatureCreator6CreateEPNS_13RSAPrivateKeyENS0_13HashAlgorithmE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto16SignatureCreator6CreateEPNS_13RSAPrivateKeyENS0_13HashAlgorithmE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto16SignatureCreator6CreateEPNS_13RSAPrivateKeyENS0_13HashAlgorithmE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto16SignatureCreator6UpdateEPKhi");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto16SignatureCreator6UpdateEPKhi, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto16SignatureCreator6UpdateEPKhi\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto16SignatureCreator5FinalEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto16SignatureCreator5FinalEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto16SignatureCreator5FinalEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto16SignatureCreatorD1Ev");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto16SignatureCreatorD1Ev, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto16SignatureCreatorD1Ev\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN3net9x509_util25CryptoBufferAsStringPieceEPK16crypto_buffer_st");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN3net9x509_util25CryptoBufferAsStringPieceEPK16crypto_buffer_st, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN3net9x509_util25CryptoBufferAsStringPieceEPK16crypto_buffer_st\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto16SignatureCreator4SignEPNS_13RSAPrivateKeyENS0_13HashAlgorithmEPKhiPNSt4__Cr6vectorIhNS6_9allocatorIhEEEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto16SignatureCreator4SignEPNS_13RSAPrivateKeyENS0_13HashAlgorithmEPKhiPNSt4__Cr6vectorIhNS6_9allocatorIhEEEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto16SignatureCreator4SignEPNS_13RSAPrivateKeyENS0_13HashAlgorithmEPKhiPNSt4__Cr6vectorIhNS6_9allocatorIhEEEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK6crypto13RSAPrivateKey4CopyEv");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK6crypto13RSAPrivateKey4CopyEv, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK6crypto13RSAPrivateKey4CopyEv\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto4Aead4InitEN4base4spanIKhLm18446744073709551615EEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto4Aead4InitEN4base4spanIKhLm18446744073709551615EEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto4Aead4InitEN4base4spanIKhLm18446744073709551615EEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN3net9x509_util26CreateKeyAndSelfSignedCertERKNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEjN4base4TimeESB_PNS1_10unique_ptrIN6crypto13RSAPrivateKeyENS1_14default_deleteISE_EEEEPS7_");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN3net9x509_util26CreateKeyAndSelfSignedCertERKNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEjN4base4TimeESB_PNS1_10unique_ptrIN6crypto13RSAPrivateKeyENS1_14default_deleteISE_EEEEPS7_, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN3net9x509_util26CreateKeyAndSelfSignedCertERKNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEjN4base4TimeESB_PNS1_10unique_ptrIN6crypto13RSAPrivateKeyENS1_14default_deleteISE_EEEEPS7_\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto29DecodeSubjectPublicKeyInfoNSSEN4base4spanIKhLm18446744073709551615EEE");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto29DecodeSubjectPublicKeyInfoNSSEN4base4spanIKhLm18446744073709551615EEE, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto29DecodeSubjectPublicKeyInfoNSSEN4base4spanIKhLm18446744073709551615EEE\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN6crypto13EnsureNSSInitEv");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN6crypto13EnsureNSSInitEv, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN6crypto13EnsureNSSInitEv\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZN3net15NSSCertDatabaseC1ENSt4__Cr10unique_ptrI15PK11SlotInfoStrN6crypto12NSSDestroyerIS3_XadL_Z13PK11_FreeSlotEEEEEES7_");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZN3net15NSSCertDatabaseC1ENSt4__Cr10unique_ptrI15PK11SlotInfoStrN6crypto12NSSDestroyerIS3_XadL_Z13PK11_FreeSlotEEEEEES7_, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZN3net15NSSCertDatabaseC1ENSt4__Cr10unique_ptrI15PK11SlotInfoStrN6crypto12NSSDestroyerIS3_XadL_Z13PK11_FreeSlotEEEEEES7_\n");
            
        }

    } 

 
    towrap = (app_pc)dr_get_proc_address(mod->handle, "_ZNK5media19KeySystemProperties15UseAesDecryptorEv");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, wrap__ZNK5media19KeySystemProperties15UseAesDecryptorEv, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get _ZNK5media19KeySystemProperties15UseAesDecryptorEv\n");
            
        }

    } 


}

static void
event_exit(void)
{
    printf("IN EXIT\n");
    drwrap_exit();
    drmgr_exit();
}

DR_EXPORT void
dr_init(client_id_t id)
{
    /* make it easy to tell, by looking at log file, which client executed */
    dr_log(NULL, DR_LOG_ALL, 1, "Client AESjack initializing\n");

    if (dr_is_notify_on()) {
        dr_fprintf(STDERR, "Client AESjack running! See AES-Log.log files for SSL logs!\n");
    }

    printf("IN AT START OF INIT\n");

    drmgr_init();
    drwrap_init();
    dr_register_exit_event(event_exit);
    drmgr_register_module_load_event(module_load_event);
    max_lock = dr_mutex_create();
}



static void
wrap_cipher_create(void *wrapcxt, void **user_data)
{
    /* int SSL_write(SSL *ssl, const void *buf, int num);
     *
     * ssize_t gnutls_record_send(gnutls_session_t session,
     *                            const void * data, size_t sizeofdata);
     */

     printf("IN CIPHER CREATE\n");

    char *alg_name = (char *)drwrap_get_arg(wrapcxt, 0);
    uint32_t type  = (uint32_t)drwrap_get_arg(wrapcxt, 1);
    uint32_t mask = (uint32_t)drwrap_get_arg(wrapcxt, 2);

    /* By generating unique filenames (per SSL context), we are able to
     * simplify logging of SSL traffic (no file locking is re quired).
     */
    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Algorithm: %s\n"
                      "Mask: %x \n",
                      alg_name, mask);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");
    /* Error handling of logging operations isn't critical - in fact, we don't
     * even know what to do in such error conditions, so we simply return!
     */
    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    /* We assume that SSL_write always succeeds and writes the whole buffer. */
    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_lock(max_lock);
}





static void
wrap_set_key(void *wrapcxt, void **user_data)
{
    /* int SSL_write(SSL *ssl, const void *buf, int num);
     *
     * ssize_t gnutls_record_send(gnutls_session_t session,
     *                            const void * data, size_t sizeofdata);
     */
    printf("IN SET KEY\n");
    void *cipher = (void *)drwrap_get_arg(wrapcxt, 0);
    uint8_t key  = (uint8_t)drwrap_get_arg(wrapcxt, 1);
    unsigned int keylen = (unsigned int)drwrap_get_arg(wrapcxt, 2);

    /* By generating unique filenames (per SSL context), we are able to
     * simplify logging of SSL traffic (no file locking is required).
     */
    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Key: %x\n"
                      "Keylen: %x \n",
                      key, keylen);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");
    /* Error handling of logging operations isn't critical - in fact, we don't
     * even know what to do in such error conditions, so we simply return!
     */
    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    /* We assume that SSL_write always succeeds and writes the whole buffer. */
    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
}

static void
wrap_AES_encrypt(void *wrapcxt, void **user_data)
{
    /* int SSL_write(SSL *ssl, const void *buf, int num);
     *
     * ssize_t gnutls_record_send(gnutls_session_t session,
     *                            const void * data, size_t sizeofdata);
     */
    printf("IN ENCRYPT\n");
    void *cipher = (void *)drwrap_get_arg(wrapcxt, 0);
    uint8_t *dest  = (uint8_t *)drwrap_get_arg(wrapcxt, 1);
    uint8_t *src = (uint8_t *)drwrap_get_arg(wrapcxt, 2);

    /* By generating unique filenames (per SSL context), we are able to
     * simplify logging of SSL traffic (no file locking is required).
     */
    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    uint8_t val = 1;
    int count = 0;
    FILE *fp;

    dr_mutex_lock(max_lock);

    while(val != 0){
        val = src[count];
        dr_snprintf(buf, 512,"src-encrypt: %x \n", val);
        filename[511] = '\0';
        fp = fopen(filename, "ab+");
    /* Error handling of logging operations isn't critical - in fact, we don't
     * even know what to do in such error conditions, so we simply return!
     */
        if (!fp) {
            dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
            return;
        }

    /* We assume that SSL_write always succeeds and writes the whole buffer. */
        fwrite(buf, 1, sizeof(buf), fp);
    
    }
    count+=1;
    fclose(fp);
    dr_mutex_unlock(max_lock);
}

static void
wrap_AES_decrypt(void *wrapcxt,  void **user_data)
{
    /* int SSL_write(SSL *ssl, const void *buf, int num);
     *
     * ssize_t gnutls_record_send(gnutls_session_t session,
     *                            const void * data, size_t sizeofdata);
     */
    printf("IN DECRYPT\n");
    void *cipher = (void *)drwrap_get_arg(wrapcxt, 0);
    uint8_t *dest  = (uint8_t *)drwrap_get_arg(wrapcxt, 1);
    uint8_t *src = (uint8_t *)drwrap_get_arg(wrapcxt, 2);

    /* By generating unique filenames (per SSL context), we are able to
     * simplify logging of SSL traffic (no file locking is required).
     */
    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    uint8_t val = 1;
    int count = 0;
    FILE *fp;
    dr_mutex_lock(max_lock);
    while(val != 0){
        val = src[count];
        dr_snprintf(buf, 512,"src-decrypt: %x \n", val);
        filename[511] = '\0';
        fp = fopen(filename, "ab+");
    /* Error handling of logging operations isn't critical - in fact, we don't
     * even know what to do in such error conditions, so we simply return!
     */
        if (!fp) {
            dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
            return;
        }

    /* We assume that SSL_write always succeeds and writes the whole buffer. */
        fwrite(buf, 1, sizeof(buf), fp);
    
    }
    count+=1;
    fclose(fp);
    dr_mutex_unlock(max_lock);
}

static void
wrap_microphone_read(void *wrapcxt,  void **user_data)
{
    /* int SSL_write(SSL *ssl, const void *buf, int num);
     *
     * ssize_t gnutls_record_send(gnutls_session_t session,
     *                            const void * data, size_t sizeofdata);
     */
    printf("IN MICROPHONE READER\n");
    void *pcm = (void *)drwrap_get_arg(wrapcxt, 0);
    uint32_t *buffer  = (uint32_t *)drwrap_get_arg(wrapcxt, 1);
    unsigned long frames = (unsigned long)drwrap_get_arg(wrapcxt, 2);

    /* By generating unique filenames (per SSL context), we are able to
     * simplify logging of SSL traffic (no file locking is required).
     */
    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    uint32_t val = 1;
    int count = 0;
    FILE *fp;

    dr_mutex_lock(max_lock);
    while(val != 0){
        val = (uint32_t)buffer[count];
        dr_snprintf(buf, 512,"src-decrypt: %x \n", val);
        filename[511] = '\0';
        fp = fopen(filename, "ab+");
    /* Error handling of logging operations isn't critical - in fact, we don't
     * even know what to do in such error conditions, so we simply return!
     */
        if (!fp) {
            dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
            return;
        }

    /* We assume that SSL_write always succeeds and writes the whole buffer. */
        fwrite(buf, 1, sizeof(buf), fp);
    
    }
    count+=1;
    
    fclose(fp);
    dr_mutex_unlock(max_lock);
}


static void
wrap_pa_mic(void *wrapcxt,  void **user_data)
{
    /* int SSL_write(SSL *ssl, const void *buf, int num);
     *
     * ssize_t gnutls_record_send(gnutls_session_t session,
     *                            const void * data, size_t sizeofdata);
     */
    printf("IN MICROPHONE READER PULSE\n");
    void *pcm = (void *)drwrap_get_arg(wrapcxt, 0);
    void *no_idea  = (void *)drwrap_get_arg(wrapcxt, 1);
    uint32_t *buffer = (uint32_t *)drwrap_get_arg(wrapcxt, 2);

    /* By generating unique filenames (per SSL context), we are able to
     * simplify logging of SSL traffic (no file locking is required).
     */
    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    uint32_t val = 1;
    int count = 0;
    FILE *fp;

    dr_mutex_lock(max_lock);
    while(val != 0){
        val = (uint32_t)buffer[count];
        dr_snprintf(buf, 512,"src-decrypt: %x \n", val);
        filename[511] = '\0';
        fp = fopen(filename, "ab+");
    /* Error handling of logging operations isn't critical - in fact, we don't
     * even know what to do in such error conditions, so we simply return!
     */
        if (!fp) {
            dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
            return;
        }

    /* We assume that SSL_write always succeeds and writes the whole buffer. */
        fwrite(buf, 1, sizeof(buf), fp);
    
    }
    count+=1;
    
    dr_mutex_unlock(max_lock);
    fclose(fp);
}

static void
wrap_ssl_privkey(void *wrapcxt,  void **user_data)
{
    printf("IN Private Key\n");
    void *key = (void *)drwrap_get_arg(wrapcxt, 0);

    /* By generating unique filenames (per SSL context), we are able to
     * simplify logging of SSL traffic (no file locking is required).
     */
    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Key: %x\n", key);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");
    /* Error handling of logging operations isn't critical - in fact, we don't
     * even know what to do in such error conditions, so we simply return!
     */
    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    /* We assume that SSL_write always succeeds and writes the whole buffer. */
    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
}

static void
wrap_ssl_decode_auth_key(void *wrapcxt,  void **user_data)
{
    printf("IN authkey decode\n");
    void *arena = (void *)drwrap_get_arg(wrapcxt, 0);
    void *encoded_item = (void *)drwrap_get_arg(wrapcxt, 1);


    /* By generating unique filenames (per SSL context), we are able to
     * simplify logging of SSL traffic (no file locking is required).
     */
    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    int len = dr_snprintf(buf, 512, "areana: %x\t encoded_item: %x\n", arena, encoded_item);
    
    filename[len] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");
    /* Error handling of logging operations isn't critical - in fact, we don't
     * even know what to do in such error conditions, so we simply return!
     */
    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    /* We assume that SSL_write always succeeds and writes the whole buffer. */
    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
}

static void
wrap_printf(void *wrapcxt,  void **user_data)
{
    printf("IN Printf\n");
    char *str = (char *)drwrap_get_arg(wrapcxt, 0);

    /* By generating unique filenames (per SSL context), we are able to
     * simplify logging of SSL traffic (no file locking is required).
     */
    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Printing: %s\n", str);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");
    /* Error handling of logging operations isn't critical - in fact, we don't
     * even know what to do in such error conditions, so we simply return!
     */
    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    /* We assume that SSL_write always succeeds and writes the whole buffer. */
    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
}

static void
wrap_preferred_cipher(void *wrapcxt,  void **user_data)
{
    printf("IN SEC_ASN1DecodeItem\n");
    long which = (long)drwrap_get_arg(wrapcxt, 0);
    int on = (int)drwrap_get_arg(wrapcxt, 1);

    /* By generating unique filenames (per SSL context), we are able to
     * simplify logging of SSL traffic (no file locking is required).
     */
    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n On: %d", which, on);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");
    /* Error handling of logging operations isn't critical - in fact, we don't
     * even know what to do in such error conditions, so we simply return!
     */
    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    /* We assume that SSL_write always succeeds and writes the whole buffer. */
    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
}

static void wrap__ZN3net9x509_util18CreateCryptoBufferERKN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN3net9x509_util18CreateCryptoBufferERKN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK4GURL21SchemeIsCryptographicEv(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK4GURL21SchemeIsCryptographicEv\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto4HMACC1ENS0_13HashAlgorithmE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto4HMACC1ENS0_13HashAlgorithmE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK6crypto4HMAC12DigestLengthEv(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK6crypto4HMAC12DigestLengthEv\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK6crypto4HMAC4SignEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPhm(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK6crypto4HMAC4SignEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPhm\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto4HMACD1Ev(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto4HMACD1Ev\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto4HMAC4InitEPKhm(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto4HMAC4InitEPKhm\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto12SymmetricKey6ImportENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto12SymmetricKey6ImportENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto9Encryptor4InitEPKNS_12SymmetricKeyENS0_4ModeEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto9Encryptor4InitEPKNS_12SymmetricKeyENS0_4ModeEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto9EncryptorC1Ev(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto9EncryptorC1Ev\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto9Encryptor10SetCounterEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto9Encryptor10SetCounterEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto9Encryptor7EncryptEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto9Encryptor7EncryptEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto9Encryptor7DecryptEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto9Encryptor7DecryptEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto9EncryptorD1Ev(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto9EncryptorD1Ev\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto10SecureHash6CreateENS0_9AlgorithmE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto10SecureHash6CreateENS0_9AlgorithmE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto16SHA256HashStringEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto16SHA256HashStringEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK6crypto13RSAPrivateKey15ExportPublicKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK6crypto13RSAPrivateKey15ExportPublicKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto13RSAPrivateKey24CreateFromPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto13RSAPrivateKey24CreateFromPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto13RSAPrivateKey6CreateEt(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto13RSAPrivateKey6CreateEt\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK6crypto13RSAPrivateKey16ExportPrivateKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK6crypto13RSAPrivateKey16ExportPrivateKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto13RSAPrivateKeyD1Ev(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto13RSAPrivateKeyD1Ev\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto17SignatureVerifierC1Ev(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto17SignatureVerifierC1Ev\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto17SignatureVerifier10VerifyInitENS0_18SignatureAlgorithmEN4base4spanIKhLm18446744073709551615EEES5_(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto17SignatureVerifier10VerifyInitENS0_18SignatureAlgorithmEN4base4spanIKhLm18446744073709551615EEES5_\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto17SignatureVerifier12VerifyUpdateEN4base4spanIKhLm18446744073709551615EEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto17SignatureVerifier12VerifyUpdateEN4base4spanIKhLm18446744073709551615EEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto17SignatureVerifier11VerifyFinalEv(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto17SignatureVerifier11VerifyFinalEv\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto17SignatureVerifierD1Ev(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto17SignatureVerifierD1Ev\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto16SHA256HashStringEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPvm(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto16SHA256HashStringEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEEPvm\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap_CRYPTO_BUFFER_data(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN CRYPTO_BUFFER_data\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap_CRYPTO_BUFFER_len(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN CRYPTO_BUFFER_len\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK6crypto4HMAC6VerifyEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK6crypto4HMAC6VerifyEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN8switches23kEnableWebRtcSrtpAesGcmE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN8switches23kEnableWebRtcSrtpAesGcmE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN8features24kImpulseScrollAnimationsE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN8features24kImpulseScrollAnimationsE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN3net18ClientCertStoreNSSC1ERKN4base17RepeatingCallbackIFPN6crypto36CryptoModuleBlockingPasswordDelegateERKNS_12HostPortPairEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN3net18ClientCertStoreNSSC1ERKN4base17RepeatingCallbackIFPN6crypto36CryptoModuleBlockingPasswordDelegateERKNS_12HostPortPairEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto9RandBytesEPvm(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto9RandBytesEPvm\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto12ECPrivateKey6CreateEv(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto12ECPrivateKey6CreateEv\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto12ECPrivateKey24CreateFromPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto12ECPrivateKey24CreateFromPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK6crypto12ECPrivateKey16ExportPrivateKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK6crypto12ECPrivateKey16ExportPrivateKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto12ECPrivateKeyD1Ev(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto12ECPrivateKeyD1Ev\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto18ECSignatureCreator6CreateEPNS_12ECPrivateKeyE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto18ECSignatureCreator6CreateEPNS_12ECPrivateKeyE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto9RandBytesEN4base4spanIhLm18446744073709551615EEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto9RandBytesEN4base4spanIhLm18446744073709551615EEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK6crypto12ECPrivateKey18ExportRawPublicKeyEPNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK6crypto12ECPrivateKey18ExportRawPublicKeyEPNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK6crypto12ECPrivateKey15ExportPublicKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK6crypto12ECPrivateKey15ExportPublicKeyEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto14SecureMemEqualEPKvS1_m(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto14SecureMemEqualEPKvS1_m\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto4AeadC1ENS0_13AeadAlgorithmE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto4AeadC1ENS0_13AeadAlgorithmE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK6crypto4Aead9KeyLengthEv(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK6crypto4Aead9KeyLengthEv\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto4Aead4InitEPKNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto4Aead4InitEPKNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK6crypto4Aead11NonceLengthEv(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK6crypto4Aead11NonceLengthEv\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK6crypto4Aead4SealEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_S6_PNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK6crypto4Aead4SealEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_S6_PNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto4AeadD1Ev(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto4AeadD1Ev\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto10HkdfSha256EN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES5_S5_m(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto10HkdfSha256EN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES5_S5_m\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK6crypto4Aead4OpenEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_S6_PNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK6crypto4Aead4OpenEN4base16BasicStringPieceIcNSt4__Cr11char_traitsIcEEEES6_S6_PNS3_12basic_stringIcS5_NS3_9allocatorIcEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto12SymmetricKey32DeriveKeyFromPasswordUsingPbkdf2ENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEESA_mm(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto12SymmetricKey32DeriveKeyFromPasswordUsingPbkdf2ENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEESA_mm\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto12SymmetricKey32DeriveKeyFromPasswordUsingScryptENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEESA_mmmmm(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto12SymmetricKey32DeriveKeyFromPasswordUsingScryptENS0_9AlgorithmERKNSt4__Cr12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEESA_mmmmm\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN3gcm12GCMStoreImplC1ERKN4base8FilePathEb13scoped_refptrINS1_19SequencedTaskRunnerEENSt4__Cr10unique_ptrINS_9EncryptorENS8_14default_deleteISA_EEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN3gcm12GCMStoreImplC1ERKN4base8FilePathEb13scoped_refptrINS1_19SequencedTaskRunnerEENSt4__Cr10unique_ptrINS_9EncryptorENS8_14default_deleteISA_EEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK6crypto12ECPrivateKey4CopyEv(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK6crypto12ECPrivateKey4CopyEv\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto12ECPrivateKey33CreateFromEncryptedPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto12ECPrivateKey33CreateFromEncryptedPrivateKeyInfoEN4base4spanIKhLm18446744073709551615EEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto10HkdfSha256EN4base4spanIKhLm18446744073709551615EEES3_S3_m(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto10HkdfSha256EN4base4spanIKhLm18446744073709551615EEES3_S3_m\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK6crypto4HMAC4SignEN4base4spanIKhLm18446744073709551615EEENS2_IhLm18446744073709551615EEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK6crypto4HMAC4SignEN4base4spanIKhLm18446744073709551615EEENS2_IhLm18446744073709551615EEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK6crypto4HMAC6VerifyEN4base4spanIKhLm18446744073709551615EEES4_(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK6crypto4HMAC6VerifyEN4base4spanIKhLm18446744073709551615EEES4_\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN3net15X509Certificate12IsSelfSignedEPK16crypto_buffer_st(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN3net15X509Certificate12IsSelfSignedEPK16crypto_buffer_st\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto16SignatureCreator6CreateEPNS_13RSAPrivateKeyENS0_13HashAlgorithmE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto16SignatureCreator6CreateEPNS_13RSAPrivateKeyENS0_13HashAlgorithmE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto16SignatureCreator6UpdateEPKhi(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto16SignatureCreator6UpdateEPKhi\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto16SignatureCreator5FinalEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto16SignatureCreator5FinalEPNSt4__Cr6vectorIhNS1_9allocatorIhEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto16SignatureCreatorD1Ev(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto16SignatureCreatorD1Ev\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN3net9x509_util25CryptoBufferAsStringPieceEPK16crypto_buffer_st(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN3net9x509_util25CryptoBufferAsStringPieceEPK16crypto_buffer_st\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto16SignatureCreator4SignEPNS_13RSAPrivateKeyENS0_13HashAlgorithmEPKhiPNSt4__Cr6vectorIhNS6_9allocatorIhEEEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto16SignatureCreator4SignEPNS_13RSAPrivateKeyENS0_13HashAlgorithmEPKhiPNSt4__Cr6vectorIhNS6_9allocatorIhEEEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK6crypto13RSAPrivateKey4CopyEv(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK6crypto13RSAPrivateKey4CopyEv\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto4Aead4InitEN4base4spanIKhLm18446744073709551615EEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto4Aead4InitEN4base4spanIKhLm18446744073709551615EEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN3net9x509_util26CreateKeyAndSelfSignedCertERKNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEjN4base4TimeESB_PNS1_10unique_ptrIN6crypto13RSAPrivateKeyENS1_14default_deleteISE_EEEEPS7_(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN3net9x509_util26CreateKeyAndSelfSignedCertERKNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEjN4base4TimeESB_PNS1_10unique_ptrIN6crypto13RSAPrivateKeyENS1_14default_deleteISE_EEEEPS7_\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto29DecodeSubjectPublicKeyInfoNSSEN4base4spanIKhLm18446744073709551615EEE(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto29DecodeSubjectPublicKeyInfoNSSEN4base4spanIKhLm18446744073709551615EEE\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN6crypto13EnsureNSSInitEv(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN6crypto13EnsureNSSInitEv\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZN3net15NSSCertDatabaseC1ENSt4__Cr10unique_ptrI15PK11SlotInfoStrN6crypto12NSSDestroyerIS3_XadL_Z13PK11_FreeSlotEEEEEES7_(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZN3net15NSSCertDatabaseC1ENSt4__Cr10unique_ptrI15PK11SlotInfoStrN6crypto12NSSDestroyerIS3_XadL_Z13PK11_FreeSlotEEEEEES7_\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
static void wrap__ZNK5media19KeySystemProperties15UseAesDecryptorEv(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN _ZNK5media19KeySystemProperties15UseAesDecryptorEv\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "AES-Log.log");

    char buf[512];

    dr_snprintf(buf, 512, "Which: %ld\n", which);
    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }

    fwrite(buf, 1, sizeof(buf), fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
