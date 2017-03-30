//
//  NJSX509.cpp
//  NJSX509
//
//  Created by Maxim Gotlib on 2/26/17.
//  Copyright © 2017 Maxim Gotlib. All rights reserved.
//

#include "NJSX509.h"

#if __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdocumentation"
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if __clang__
#pragma clang diagnostic pop
#endif

#if _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#endif

#include <string>

using namespace NJSX509;

using v8::FunctionCallbackInfo;
using v8::PropertyCallbackInfo;
using v8::Isolate;
using v8::Local;
using v8::MaybeLocal;
using v8::Object;
using v8::String;
using v8::Number;
using v8::Array;
using v8::Value;
using v8::Function;
using v8::Exception;
using v8::FunctionTemplate;
using v8::Context;
using v8::Persistent;

static bool __getASN1Time(ASN1_TIME* time, struct tm& t);
#if NOT_USED_YET
static int __compareTime(const struct tm& t1, const struct tm& t2, bool subDayPrecision = false);
static int __compareASN1Time(ASN1_TIME* t1, ASN1_TIME* t2, bool subDayPrecision = false);
#endif
static int __guessPadding(Isolate* isolate, Local<Value> arg);

Persistent<Function> NJSX509Certificate::constructor_;

#if __clang__
#pragma mark - X509Certificate implementation
#endif

NJSX509Certificate::NJSX509Certificate(X509* cert, EVP_PKEY* privateKey)
    : x509Certificate_(cert)
    , privateKey_(privateKey)
    , subject_(nullptr)
    , issuer_(nullptr)
    , commonName_(nullptr)
    , fingerprint_(nullptr)
{
    if( x509Certificate_ != nullptr )
    {
        X509_up_ref(x509Certificate_);
    }
    if( privateKey_ != nullptr )
    {
        EVP_PKEY_up_ref(privateKey_);
    }
}

NJSX509Certificate::~NJSX509Certificate()
{
    if( x509Certificate_ != nullptr )
    {
        X509_free(x509Certificate_);
        x509Certificate_ = nullptr;
    }
    
    if( privateKey_ != nullptr )
    {
        EVP_PKEY_free(privateKey_);
        privateKey_ = nullptr;
    }
    
    if( subject_ != nullptr )
    {
        ::free(subject_);
        subject_ = nullptr;
    }
    
    if( issuer_ != nullptr )
    {
        free(issuer_);
        issuer_ = nullptr;
    }
    
    if( commonName_ != nullptr )
    {
        ::free(commonName_);
        commonName_ = nullptr;
    }
    
    if( fingerprint_ != nullptr )
    {
        ::free(fingerprint_);
        fingerprint_ = nullptr;
    }
}

X509* NJSX509Certificate::newCertificateFromPEM(const char* pemCertString, size_t dataLength)
{
    if( pemCertString == nullptr || dataLength == 0 )
    {
        return nullptr;
    }
    
    BIO* bio = BIO_new_mem_buf((void*)pemCertString, static_cast<int>(dataLength));
    assert(bio != nullptr);
    if( bio == nullptr )
    {
        return nullptr;
    }
    
    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return cert;
}

X509* NJSX509Certificate::newCertificateFromDER(const void* derCertData, size_t dataSize)
{
    return newCertificateFromDERInc(derCertData, dataSize);
}

X509* NJSX509Certificate::newCertificateFromDERInc(const void*& derCertData, size_t& dataSize)
{
    assert(derCertData != nullptr);
    assert(dataSize > 0);
    if( derCertData == nullptr || dataSize == 0 )
    {
        return nullptr;
    }
    
    const unsigned char* data = reinterpret_cast<const unsigned char*>(derCertData);
    const unsigned char* dataIn = data;
    X509* cert = d2i_X509(nullptr, &dataIn, static_cast<long>(dataSize));
    if( cert != nullptr )
    {
        derCertData = reinterpret_cast<const void*>(dataIn);
        dataSize -= static_cast<size_t>(dataIn - data);
    }
    return cert;
}

X509* NJSX509Certificate::newCertificateFromDER(BIO* bio)
{
    X509* cert = d2i_X509_bio(bio, NULL);
    return cert;
}

X509* NJSX509Certificate::newCertificateFromBase64DER(const char* derCertData, size_t dataSize)
{
    assert(derCertData != nullptr);
    assert(dataSize > 0);
    if( derCertData == nullptr || dataSize == 0 )
    {
        return nullptr;
    }
    
    BIO* b64 = BIO_new(BIO_f_base64());
    assert(b64 != nullptr);
    if( b64 == nullptr )
    {
        return nullptr;
    }
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* bmem = BIO_new_mem_buf(const_cast<char*>(derCertData), static_cast<int>(dataSize));
    assert(bmem != nullptr);
    if( bmem == nullptr )
    {
        BIO_free(b64);
        return nullptr;
    }
    bmem = BIO_push(b64, bmem);
    
    X509* cert = newCertificateFromDER(bmem);
    
    BIO_free_all(bmem);
    return cert;
}

EVP_PKEY* NJSX509Certificate::newPrivateKeyFromPEM(BIO* bio, const char* passphrase)
{
    if( passphrase == nullptr )
    {
        passphrase = "";
    }
    EVP_PKEY* pk = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, (void*)passphrase);
    return pk;
}

EVP_PKEY* NJSX509Certificate::newPrivateKeyFromPEM(const char* pemPKString, size_t dataLength, const char* passphrase)
{
    assert(pemPKString != nullptr);
    assert(dataLength > 0);
    if( pemPKString == nullptr || dataLength == 0 )
    {
        return nullptr;
    }

    BIO* bmem = BIO_new_mem_buf(const_cast<char*>(pemPKString), static_cast<int>(dataLength));
    assert(bmem != nullptr);
    if( bmem == nullptr )
    {
        return nullptr;
    }

    return newPrivateKeyFromPEM(bmem, passphrase);
}

#if __clang__
#pragma mark - Native certificate attribute acceessor methods.
#endif

const char* NJSX509Certificate::getSubject() const
{
    if( subject_ != nullptr )
    {
        return subject_;
    }
    
    if( x509Certificate_ == nullptr )
    {
        return nullptr;
    }
    
    subject_ = X509_NAME_oneline(X509_get_subject_name(x509Certificate_), NULL, 0);
    
    return subject_;
}

const char* NJSX509Certificate::getIssuer() const
{
    if( issuer_ != nullptr )
    {
        return issuer_;
    }
    
    if( x509Certificate_ == nullptr )
    {
        return nullptr;
    }

    issuer_ = X509_NAME_oneline(X509_get_issuer_name(x509Certificate_), NULL, 0);
    return issuer_;
}

const char* NJSX509Certificate::getCommonName() const
{
    if( commonName_ != nullptr )
    {
        return commonName_;
    }
    
    if( x509Certificate_ == nullptr )
    {
        return nullptr;
    }
    
    X509_NAME* subj = X509_get_subject_name(x509Certificate_);
    
    if( subj == nullptr )
    {
        return nullptr;
    }
    int textLen = X509_NAME_get_text_by_NID(subj, NID_commonName, nullptr, 0);
    if( textLen <= 0 )
    {
        return nullptr;
    }
    
    commonName_ = reinterpret_cast<char*>(::malloc(static_cast<size_t>(textLen + 1)));
    if( commonName_ == nullptr )
    {
        return nullptr;
    }
    
    X509_NAME_get_text_by_NID(subj, NID_commonName, commonName_, textLen + 1);
    commonName_[textLen] = '\0';

    return commonName_;
}

const char* NJSX509Certificate::getFingerprint() const
{
    if( fingerprint_ != nullptr )
    {
        return fingerprint_;
    }
    
    if( x509Certificate_ == nullptr )
    {
        return nullptr;
    }

    unsigned char buff[EVP_MAX_MD_SIZE];
    unsigned int n = 0;
    X509_digest(x509Certificate_, EVP_sha1(), buff, &n);
    
    if( n > 0 )
    {
        fingerprint_ = reinterpret_cast<char*>(::malloc(static_cast<size_t>(3 * n + 1)));
        if( fingerprint_ == nullptr )
        {
            return nullptr;
        }
        auto* ptr = fingerprint_;
        auto* mdPtr = buff;
        for( unsigned int i = 0; i < n - 1; ++i, ++mdPtr )
        {
            auto ch = (*mdPtr & 0xF0) >> 4;
            *ptr++ = ch > 9 ? 'A' -10 + ch : '0' + ch;
            ch = *mdPtr & 0x0F;
            *ptr++ = ch > 9 ? 'A' -10 + ch : '0' + ch;
            *ptr++ = ':';
        }
        auto ch = (*mdPtr & 0xF0) >> 4;
        *ptr++ = ch > 9 ? 'A' -10 + ch : '0' + ch;
        ch = *mdPtr & 0x0F;
        *ptr++ = ch > 9 ? 'A' -10 + ch : '0' + ch;
        *ptr = '\0';
    }
    
    return fingerprint_;
}

time_t NJSX509Certificate::getValidFrom() const
{
    if( x509Certificate_ == nullptr )
    {
        return 0;
    }

    ASN1_TIME* not_before = X509_get_notBefore(x509Certificate_);
    struct tm tm;
    if( !__getASN1Time(not_before, tm) )
    {
        return 0;
    }
    
    return mktime(&tm);
}

time_t NJSX509Certificate::getNotValidAfter() const
{
    if( x509Certificate_ == nullptr )
    {
        return 0;
    }
    
    ASN1_TIME* not_after = X509_get_notAfter(x509Certificate_);
    struct tm tm;
    if( !__getASN1Time(not_after, tm) )
    {
        return 0;
    }
    
    return mktime(&tm);
}

void NJSX509Certificate::setPrivateKey(EVP_PKEY* pk)
{
    if( privateKey_ == pk )
    {
        return;
    }
    if( privateKey_ != nullptr )
    {
        EVP_PKEY_free(privateKey_);
    }
    privateKey_ = pk;
    if( privateKey_ != nullptr )
    {
        EVP_PKEY_up_ref(privateKey_);
    }
}

size_t NJSX509Certificate::encryptPublic(const void* inData, size_t inSize, void** outData, int padding)
{
    assert(inData != nullptr);
    if( inData == nullptr )
    {
        return 0;
    }

    assert(outData != nullptr);
    if( outData == nullptr )
    {
        return 0;
    }

    if( x509Certificate_ == nullptr )
    {
        return 0;
    }

    EVP_PKEY* publicKey = X509_get_pubkey(x509Certificate_);
    if( publicKey == nullptr )
    {
        return 0;
    }

    bool allocatedBuffer = false;
    size_t outlen = 0;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(publicKey, NULL);
    if( ctx == nullptr )
    {
        goto done;
    }
    
    if( EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0 )
    {
        goto done;
    }
    
    if( EVP_PKEY_encrypt(ctx, NULL, &outlen, (const unsigned char*)inData, inSize) <= 0 )
    {
        goto done;
    }
    
    if( outlen == 0 || outData == nullptr )
    {
        goto done;
    }
    
    if( *outData == nullptr )
    {
        *outData = ::malloc(outlen);
        if( *outData == nullptr )
        {
            outlen = 0;
            goto done;
        }
        allocatedBuffer = true;
    }
    
    if( EVP_PKEY_encrypt(ctx, (unsigned char*)*outData, &outlen, (const unsigned char*)inData, inSize) <= 0 )
    {
        if( allocatedBuffer )
        {
            ::free(*outData);
            *outData = nullptr;
        }
        outlen = 0;
    }
    
done:
    if( ctx != NULL )
    {
        EVP_PKEY_CTX_free(ctx);
    }
    EVP_PKEY_free(publicKey);
    
    return outlen;
}

size_t NJSX509Certificate::decryptPrivate(const void* inData, size_t inSize, void** outData, int padding)
{
    assert(inData != nullptr);
    if( inData == nullptr )
    {
        return 0;
    }
    
    assert(outData != nullptr);
    if( outData == nullptr )
    {
        return 0;
    }

    if( privateKey_ == nullptr )
    {
        return 0;
    }
    
    bool allocatedBuffer = false;
    size_t outlen = 0;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey_, NULL);
    if( ctx == nullptr )
    {
        goto done;
    }
    
    if( EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0 )
    {
        goto done;
    }
    
    if( EVP_PKEY_decrypt(ctx, NULL, &outlen, (const unsigned char*)inData, inSize) <= 0 )
    {
        goto done;
    }
    
    if( outlen == 0 || outData == nullptr )
    {
        goto done;
    }
    
    if( *outData == nullptr )
    {
        *outData = ::malloc(outlen);
        if( *outData == nullptr )
        {
            outlen = 0;
            goto done;
        }
        allocatedBuffer = true;
    }
    
    if( EVP_PKEY_decrypt(ctx, (unsigned char*)*outData, &outlen, (const unsigned char*)inData, inSize) <= 0 )
    {
        if( allocatedBuffer )
        {
            ::free(*outData);
            *outData = nullptr;
        }
        outlen = 0;
    }
    
done:
    if( ctx != NULL )
    {
        EVP_PKEY_CTX_free(ctx);
    }
    
    return outlen;
}

X509* NJSX509Certificate::issueNewCertificate(const char* cname, size_t cnameLen, unsigned serialNo, EVP_PKEY* privateKey)
{
    assert(cname != nullptr);
    if( cname == nullptr )
    {
        return nullptr;
    }
    
    if( x509Certificate_ == nullptr )
    {
        return nullptr;
    }
    
    if( privateKey == nullptr )
    {
        privateKey = privateKey_;
    }
    if( privateKey == nullptr )
    {
        return nullptr;
    }
    
    X509* newCert = X509_new();
    assert(newCert != nullptr);
    if( newCert == nullptr )
    {
        return nullptr;
    }
    
    if( X509_set_version(newCert, 2L) != 1 )
    {
    free_cert_and_return_error:
        X509_free(newCert);
        return nullptr;
    }
    
    ASN1_INTEGER_set(X509_get_serialNumber(newCert), (long)serialNo);
    
    if( X509_gmtime_adj(X509_get_notBefore(newCert), (long)-60*60*24) == nullptr || X509_gmtime_adj(X509_get_notAfter(newCert), (long)60*60*24*365) == nullptr )
    {
        goto free_cert_and_return_error;
    }
    
    if( X509_set_pubkey(newCert, privateKey) != 1 )
    {
        goto free_cert_and_return_error;
    }
    
    X509_NAME* name = X509_get_subject_name(x509Certificate_);
    if( name == nullptr )
    {
        goto free_cert_and_return_error;
    }
    if( X509_set_issuer_name(newCert, name) != 1 )
    {
        goto free_cert_and_return_error;
    }
    
    bool ok = false;
    char* altName = nullptr;
    name = X509_NAME_dup(name);
    if( name != nullptr )
    {
        if( cnameLen == 0 )
        {
            cnameLen = ::strlen(cname);
        }
        if( cnameLen > 40 )
        {
            // Target host name is too long to fit X509 subject cname field size restrictions.
            altName = (char*) ::malloc(cnameLen + 4 /* "DNS:" */ + 1);
            assert(altName != nullptr);
            if( altName != nullptr )
            {
                memcpy(altName, "DNS:", 5);
                memcpy(altName + 4, cname, cnameLen + 1);
            }
            cname += cnameLen - 40;
        }

        int loc = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if( loc >= 0 )
        {
            X509_NAME_delete_entry(name, loc);
        }
        
        ok = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, (const unsigned char*)cname, -1, -1, 0) == 1 && X509_set_subject_name(newCert, name) == 1;
        assert(ok);
        X509_NAME_free(name);
    }
    if( !ok )
    {
        if( altName != nullptr )
        {
            ::free(altName);
        }
        goto free_cert_and_return_error;
    }
    
    
    if( altName != nullptr )
    {
        // Add long target host name as x509v3 extension.
        X509V3_CTX ctx;
        X509V3_set_ctx(&ctx, x509Certificate_, newCert, NULL, NULL, 0);
#ifdef OPENSSL_IS_BORINGSSL
        X509_EXTENSION *ext = X509V3_EXT_nconf(NULL, &ctx, (char*)"subjectAltName", altName);
#else
        X509_EXTENSION *ext = X509V3_EXT_conf(NULL, &ctx, (char*)"subjectAltName", altName);
#endif // OPENSSL_IS_BORINGSSL
        if( ext != nullptr )
        {
            X509_add_ext(newCert, ext, -1);
            X509_EXTENSION_free(ext);
        }
        ::free(altName);
    }
    
    const EVP_MD* digest;
    switch( EVP_PKEY_type(privateKey->type) )
    {
#ifndef OPENSSL_IS_BORINGSSL
        case EVP_PKEY_DSA:
            digest = EVP_dss1();
            break;
#endif // OPENSSL_IS_BORINGSSL
        case EVP_PKEY_RSA:
            digest = EVP_sha256();
            break;
        default:
            assert(false);
            X509_free(newCert);
            return nullptr;
    }
    
    EVP_PKEY* signingKey = getPrivateKey();
    if( signingKey == nullptr )
    {
        signingKey = privateKey;
    }
    if( X509_sign(newCert, signingKey, digest) == 0 )
    {
        goto free_cert_and_return_error;
    }
    
    return newCert;    
}

#if __clang__
#pragma mark - Utility methods.
#endif

static bool __getASN1Time(ASN1_TIME* time, struct tm& t)
{
    assert(time != nullptr);
    if( time == nullptr )
    {
        return false;
    }
    
    const char* str = (const char*) time->data;
    if( str == nullptr )
    {
        return false;
    }
    size_t i = 0;
    
    ::memset(&t, 0, sizeof(t));
    
    if(time->type == V_ASN1_UTCTIME)
    {
        // two digit year
        t.tm_year = (str[i++] - '0') * 10;
        t.tm_year += (str[i++] - '0');
        if (t.tm_year < 70)
        {
            t.tm_year += 100;
        }
    }
    else if(time->type == V_ASN1_GENERALIZEDTIME)
    {
        // four digit year
        t.tm_year = (str[i++] - '0') * 1000;
        t.tm_year+= (str[i++] - '0') * 100;
        t.tm_year+= (str[i++] - '0') * 10;
        t.tm_year+= (str[i++] - '0');
        t.tm_year -= 1900;
    }
    t.tm_mon  = (str[i++] - '0') * 10;
    t.tm_mon += (str[i++] - '0') - 1; // -1 since January is 0 not 1.
    t.tm_mday = (str[i++] - '0') * 10;
    t.tm_mday+= (str[i++] - '0');
    t.tm_hour = (str[i++] - '0') * 10;
    t.tm_hour+= (str[i++] - '0');
    t.tm_min  = (str[i++] - '0') * 10;
    t.tm_min += (str[i++] - '0');
    t.tm_sec  = (str[i++] - '0') * 10;
    t.tm_sec += (str[i++] - '0');
    
    return true;
}

#if NOT_USED_YET
static int __compareTime(const struct tm& t1, const struct tm& t2, bool subDayPrecision)
{
    if( t1.tm_year > t2.tm_year )
    {
        return 1;
    }
    if( t1.tm_year < t2.tm_year )
    {
        return -1;
    }
    
    if( t1.tm_mon > t2.tm_mon)
    {
        return 1;
    }
    if( t1.tm_mon < t2.tm_mon)
    {
        return -1;
    }
    
    if( t1.tm_mday > t2.tm_mday)
    {
        return 1;
    }
    if( t1.tm_mday < t2.tm_mday)
    {
        return -1;
    }
    
    if( !subDayPrecision )
    {
        return 0;
    }
    
    if( t1.tm_hour > t2.tm_hour)
    {
        return 1;
    }
    if( t1.tm_hour < t2.tm_hour)
    {
        return -1;
    }
    
    if( t1.tm_min > t2.tm_min)
    {
        return 1;
    }
    if( t1.tm_min < t2.tm_min)
    {
        return -1;
    }
    
    if( t1.tm_sec > t2.tm_sec)
    {
        return 1;
    }
    if( t1.tm_sec < t2.tm_sec)
    {
        return -1;
    }
    
    return 0;
}

static int __compareASN1Time(ASN1_TIME* t1, ASN1_TIME* t2, bool subDayPrecision)
{
    if( t1 == nullptr || t2 == nullptr )
    {
        return -2;
    }
    
    struct tm tm1;
    if( !__getASN1Time(t1, tm1) )
    {
        return -3;
    }
    
    struct tm tm2;
    if( !__getASN1Time(t2, tm2) )
    {
        return -4;
    }
    
    return __compareTime(tm1, tm2, subDayPrecision);
}
#endif

bool NJSX509Certificate::CheckArguments(const FunctionCallbackInfo<Value>& args, int minNumberOfArguments, int typeArgumentIndex, CertificateDataFormat& certFormat)
{
    certFormat = CertificateDataFormat::PEM;
    Isolate* isolate = args.GetIsolate();
    if( args.Length() < minNumberOfArguments )
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments.")));
        return false;
    }
    
    if( typeArgumentIndex >= args.Length() )
    {
        return true;
    }
    if( typeArgumentIndex < 0 )
    {
        typeArgumentIndex = args.Length() - 1;
        if( typeArgumentIndex < 0 )
        {
            return true;
        }
    }
    
    String::Utf8Value typeStr(args[typeArgumentIndex]->ToString());
    if( typeStr.length() > 0 )
    {
        if( strcasecmp(*typeStr, "pem") == 0 )
        {
            return true;
        }
        if( strcasecmp(*typeStr, "der") == 0 )
        {
            certFormat = CertificateDataFormat::DER;
            return true;
        }
        if( strcasecmp(*typeStr, "base64_der") == 0 )
        {
            certFormat = CertificateDataFormat::Base64_DER;
            return true;
        }
    }
    
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Invalid certificate data type. Expected PEM (default), DER or BASE64_DER.")));
    return false;
}

#if __clang__
#pragma mark - JS prototype initialization and instantiation methods.
#endif

void NJSX509Certificate::Init(Local<Object> exports)
{
    Isolate* isolate = exports->GetIsolate();
    
    // Prepare constructor template.
    Local<FunctionTemplate> tpl = FunctionTemplate::New(isolate, New);
    tpl->SetClassName(String::NewFromUtf8(isolate, "NJSX509Certificate"));
    tpl->InstanceTemplate()->SetInternalFieldCount(1);
    
    // Populate prototype calculated properties.
    tpl->InstanceTemplate()->SetAccessor(String::NewFromUtf8(isolate, "subjectName"),
                                         stringPropertyAccessor<&NJSX509Certificate::getSubject>, nullptr, Local<Value>(), v8::AccessControl::DEFAULT, v8::PropertyAttribute::ReadOnly);
    tpl->InstanceTemplate()->SetAccessor(String::NewFromUtf8(isolate, "commonName"),
                                         stringPropertyAccessor<&NJSX509Certificate::getCommonName>, nullptr, Local<Value>(), v8::AccessControl::DEFAULT, v8::PropertyAttribute::ReadOnly);
    tpl->InstanceTemplate()->SetAccessor(String::NewFromUtf8(isolate, "issuer"),
                                         stringPropertyAccessor<&NJSX509Certificate::getIssuer>, nullptr, Local<Value>(), v8::AccessControl::DEFAULT, v8::PropertyAttribute::ReadOnly);
    tpl->InstanceTemplate()->SetAccessor(String::NewFromUtf8(isolate, "validSince"),
                                         datePropertyAccessor<&NJSX509Certificate::getValidFrom>, nullptr, Local<Value>(), v8::AccessControl::DEFAULT, v8::PropertyAttribute::ReadOnly);
    tpl->InstanceTemplate()->SetAccessor(String::NewFromUtf8(isolate, "notValidAfter"),
                                         datePropertyAccessor<&NJSX509Certificate::getNotValidAfter>, nullptr, Local<Value>(), v8::AccessControl::DEFAULT, v8::PropertyAttribute::ReadOnly);
    tpl->InstanceTemplate()->SetAccessor(String::NewFromUtf8(isolate, "publicKey"), PublicKey, nullptr, Local<Value>(), v8::AccessControl::DEFAULT, v8::PropertyAttribute::ReadOnly);
    tpl->InstanceTemplate()->SetAccessor(String::NewFromUtf8(isolate, "fingerprint"),
                                         stringPropertyAccessor<&NJSX509Certificate::getFingerprint>, nullptr, Local<Value>(), v8::AccessControl::DEFAULT, v8::PropertyAttribute::ReadOnly);
    
    // Populate prototype methods.
    NODE_SET_PROTOTYPE_METHOD(tpl, "getPrivateKey", GetPrivateKey);
    NODE_SET_PROTOTYPE_METHOD(tpl, "setPrivateKey", SetPrivateKey);
    NODE_SET_PROTOTYPE_METHOD(tpl, "encryptPublic", EncryptWithPublicKey);
    NODE_SET_PROTOTYPE_METHOD(tpl, "decryptPrivate", DecryptWithPrivateKey);
    NODE_SET_PROTOTYPE_METHOD(tpl, "issueCertificate", IssueCertificate);
    NODE_SET_PROTOTYPE_METHOD(tpl, "exportCertificate", ExportCertificate);
    
    // Persist constructor function object.
    Local<Function> func = tpl->GetFunction();
    constructor_.Reset(isolate, func);
    exports->Set(String::NewFromUtf8(isolate, "NJSX509Certificate"), func);
    
    // Add addon methods.
    NODE_SET_METHOD(exports, "importCertificateStore", ParseCertificateStore);
    NODE_SET_METHOD(exports, "importPKCS12", ParsePKCS12);
}

MaybeLocal<Object> NJSX509Certificate::NewJSInstance(Isolate* isolate, unsigned argc, Local<Value> argv[], NJSX509Certificate* wrappedObject)
{
    // Call constructor method.
    Local<Function> cons = Local<Function>::New(isolate, constructor_);
    Local<Context> context = isolate->GetCurrentContext();
    
    MaybeLocal<Object> instance = cons->NewInstance(context, argc, argv);
    if( instance.IsEmpty() )
    {
        return instance;
    }
    
    // Try to wrap the result.
    if( wrappedObject != nullptr )
    {
        wrappedObject->Wrap(instance.ToLocalChecked());
        return instance;
    }
    
    // Set null wrapped object pointer.
    instance.ToLocalChecked()->SetAlignedPointerInInternalField(0, nullptr);
    return instance;
}

void NJSX509Certificate::NewInstance(const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = args.GetIsolate();
    
    Local<Value> argv[10];
    const unsigned argc = args.Length();
    if( argc > sizeof(argv)/sizeof(*argv) )
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Too many arguments.")));
        return;
    }
    for( unsigned i = 0; i < argc; ++i )
    {
        argv[i] = args[i];
    }
    
    // Call constructor method.
    MaybeLocal<Object> instance = NewJSInstance(isolate, argc, argv);
    if( instance.IsEmpty() )
    {
        args.GetReturnValue().SetUndefined();
    }
    else
    {
        args.GetReturnValue().Set(instance.ToLocalChecked());
    }
}

#if __clang__
#pragma mark - JS NJSX509 prototype methods and property accessors.
#endif

void NJSX509Certificate::New(const FunctionCallbackInfo<Value>& args)
{
    // Get sure thefunction is invoked as constructor: `new NJSX509Certificate(...)`
    if( !args.IsConstructCall() )
    {
        // Invoked as plain function `NJSX509Certificate(...)`, turn into construct call.
        NewInstance(args);
        return;
    }
    
    // Special case - constructor called with no arguments.
    NJSX509Certificate* obj = nullptr;
    if( args.Length() == 0 )
    {
        obj = new NJSX509Certificate(nullptr);
        assert(obj != nullptr);
        Local<Object> _self = args.This();
        obj->Wrap(_self);
        args.GetReturnValue().Set(_self);
        return;
    }
    
    // Check the number of arguments passed and prepare certificate instantiation parameters.
    CertificateDataFormat certFormat = CertificateDataFormat::PEM;
    if( !CheckArguments(args, 1, 1, certFormat) )
    {
        return;
    }
    
    // Try to instantiate certificate object.
    CallWithRawDataRepresentation(args[0], [&obj, certFormat](const char* dataPtr, size_t dataLen) -> bool {
        X509* c = nullptr;
        switch( certFormat )
        {
            case CertificateDataFormat::PEM:
                c = newCertificateFromPEM(dataPtr, dataLen);
                break;
            case CertificateDataFormat::DER:
                c = newCertificateFromDER(dataPtr, dataLen);
                break;
            case CertificateDataFormat::Base64_DER:
                c = newCertificateFromBase64DER(dataPtr, dataLen);
                break;
            default:
                break;
        }
        if( c == nullptr )
        {
            return false;
        }
        obj = new NJSX509Certificate(c);
        assert(obj != nullptr);
        return obj != nullptr;
    });
    
    if( obj == nullptr )
    {
        Isolate* isolate = args.GetIsolate();
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Invalid certificate data")));
        return;
    }
    
    // Wrap native certificate object with JS object.
    obj->Wrap(args.This());
    args.GetReturnValue().Set(args.This());
}

void NJSX509Certificate::PublicKey(Local<String> __unused property, const PropertyCallbackInfo<Value>& info)
{
    NJSX509Certificate* obj = nativeObjectFromJSObject(info);
    if( obj == nullptr )
    {
        return;
    }
    
    bool ok = obj->copyPublicKey([info](BIO* mbio) {
        assert(mbio != nullptr);
        
        BUF_MEM* mbufPtr;
        BIO_get_mem_ptr(mbio, &mbufPtr);
        BIO_set_close(mbio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
        
        if( mbufPtr == nullptr )
        {
            info.GetReturnValue().SetUndefined();
            return;
        }
        
        MemBIOBufferStringResource* retResource = new MemBIOBufferStringResource(mbufPtr);
        assert(retResource != nullptr);
        if( retResource == nullptr )
        {
            info.GetReturnValue().SetUndefined();
            return;
        }
        
        info.GetReturnValue().Set(String::NewExternal(info.GetIsolate(), retResource));
    });

    if( !ok )
    {
        info.GetReturnValue().SetUndefined();
    }
}

void NJSX509Certificate::GetPrivateKey(const FunctionCallbackInfo<Value>& info)
{
    NJSX509Certificate* obj = nativeObjectFromJSObject(info);
    if( obj == nullptr )
    {
        return;
    }
    
    Local<Value> passArg;
    if( info.Length() > 0 )
    {
        passArg = info[0];
    }
    String::Utf8Value passStr(passArg->ToString());

    bool ok = copyPrivateKey(obj->getPrivateKey(), *passStr, passStr.length(), [info](BIO* mbio) {
        assert(mbio != nullptr);

        BUF_MEM* mbufPtr;
        BIO_get_mem_ptr(mbio, &mbufPtr);
        BIO_set_close(mbio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
        
        if( mbufPtr == nullptr )
        {
            info.GetReturnValue().SetUndefined();
            return;
        }
        
        MemBIOBufferStringResource* retResource = new MemBIOBufferStringResource(mbufPtr);
        assert(retResource != nullptr);
        if( retResource == nullptr )
        {
            info.GetReturnValue().SetUndefined();
            return;
        }
        
        info.GetReturnValue().Set(String::NewExternal(info.GetIsolate(), retResource));
    });
    
    if( !ok )
    {
        info.GetReturnValue().SetUndefined();
    }
}

void NJSX509Certificate::SetPrivateKey(const FunctionCallbackInfo<Value>& info)
{
    NJSX509Certificate* obj = nativeObjectFromJSObject(info);
    if( obj == nullptr )
    {
        return;
    }
    
    Isolate* isolate = info.GetIsolate();
    if( info.Length() == 0 )
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments.")));
        return;
    }

    ::std::string passphrase;
    if( info.Length() > 1 )
    {
        String::Utf8Value passStr(info[1]->ToString());
        if( passStr.length() > 0 )
        {
            passphrase.append(*passStr, passStr.length());
        }
    }
    
    bool ok = CallWithRawDataRepresentation(info[0], [&passphrase, obj, isolate](const char* pemData, size_t dataLength) -> bool {
        EVP_PKEY* pk = newPrivateKeyFromPEM(pemData, dataLength, passphrase.c_str());
        if( pk == nullptr )
        {
            std::string temp = "PrivateKey parse: ";
            temp += ERR_error_string(ERR_get_error(), nullptr);
            isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, temp.c_str())));
            return false;
        }
        obj->setPrivateKey(pk);
        EVP_PKEY_free(pk);
        return true;
    });

    if( ok )
    {
        info.GetReturnValue().Set(obj->getPrivateKey() != nullptr);
    }
}

static int __guessPadding(Isolate* isolate, Local<Value> arg)
{
    String::Utf8Value paddingName(arg->ToString());
    if( paddingName.length() > 0 )
    {
        if( strncasecmp(*paddingName, "PKCS1", paddingName.length()) == 0 )
        {
            return RSA_PKCS1_PADDING;
        }
        if( strncasecmp(*paddingName, "SSLV23", paddingName.length()) == 0 )
        {
            return RSA_SSLV23_PADDING;
        }
        if( strncasecmp(*paddingName, "NO", paddingName.length()) == 0 )
        {
            return RSA_NO_PADDING;
        }
        if( strncasecmp(*paddingName, "OAEP", paddingName.length()) == 0 )
        {
            return RSA_PKCS1_OAEP_PADDING;
        }
        if( strncasecmp(*paddingName, "X931", paddingName.length()) == 0 )
        {
            return RSA_X931_PADDING;
        }
        if( strncasecmp(*paddingName, "PKCS1_PSS", paddingName.length()) == 0 )
        {
            return RSA_PKCS1_PSS_PADDING;
        }
    }
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Encrypt public: Invalid padding. Supported are: NO, PKCS1, SSLV23, OAEP, X931, PKCS1_PSS.")));
    return -1;
}

void NJSX509Certificate::EncryptWithPublicKey(const FunctionCallbackInfo<Value>& info)
{
    NJSX509Certificate* obj = nativeObjectFromJSObject(info);
    if( obj == nullptr )
    {
        return;
    }
    
    Isolate* isolate = info.GetIsolate();
    if( obj->x509Certificate_ == nullptr )
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Encrypt public: incomplete certificate.")));
        return;
    }
    
    if( info.Length() == 0 )
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments.")));
        return;
    }

    int padding = RSA_PKCS1_PADDING;
    if( info.Length() > 1 )
    {
        padding = __guessPadding(isolate, info[1]);
        if( padding == -1 )
        {
            return;
        }
    }

    size_t outSize = 0;
    void* outData = nullptr;
    bool ok = CallWithRawDataRepresentation(info[0], [&obj, &outData, &outSize, padding, isolate](const char* inData, size_t inSize) -> bool {
        outSize = obj->encryptPublic(inData, inSize, &outData, padding);
        if( outSize == 0 )
        {
            std::string temp = "Encrypt public: ";
            temp += ERR_error_string(ERR_get_error(), nullptr);
            isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, temp.c_str())));
            return false;
        }
        return true;
    });
    if( !ok )
    {
        return;
    }
    
    assert(outSize > 0);
    assert(outData != nullptr);
    
    auto outBuff = node::Buffer::New(isolate, reinterpret_cast<char*>(outData), outSize, [](char* data, void* hint) {
        assert(data != nullptr);
        ::free(data);
    }, nullptr);
    if( outBuff.IsEmpty() )
    {
        info.GetReturnValue().SetUndefined();
    }
    else
    {
        info.GetReturnValue().Set(outBuff.ToLocalChecked());
    }
}

void NJSX509Certificate::DecryptWithPrivateKey(const FunctionCallbackInfo<Value>& info)
{
    NJSX509Certificate* obj = nativeObjectFromJSObject(info);
    if( obj == nullptr )
    {
        return;
    }
    
    Isolate* isolate = info.GetIsolate();
    if( obj->privateKey_ == nullptr )
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Decrypt private: no associated private key.")));
        return;
    }
    
    if( info.Length() == 0 )
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments.")));
        return;
    }
    
    int padding = RSA_PKCS1_PADDING;
    if( info.Length() > 1 )
    {
        padding = __guessPadding(isolate, info[1]);
        if( padding == -1 )
        {
            return;
        }
    }
    
    size_t outSize = 0;
    void* outData = nullptr;
    bool ok = CallWithRawDataRepresentation(info[0], [&obj, &outData, &outSize, padding, isolate](const char* inData, size_t inSize) -> bool {
        outSize = obj->decryptPrivate(inData, inSize, &outData, padding);
        if( outSize == 0 )
        {
            std::string temp = "Decrypt private: ";
            temp += ERR_error_string(ERR_get_error(), nullptr);
            isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, temp.c_str())));
            return false;
        }
        return true;
    });
    if( !ok )
    {
        return;
    }
    
    assert(outSize > 0);
    assert(outData != nullptr);
    
    auto outBuff = node::Buffer::New(isolate, reinterpret_cast<char*>(outData), outSize, [](char* data, void* hint) {
        assert(data != nullptr);
        free(data);
    }, nullptr);
    if( outBuff.IsEmpty() )
    {
        info.GetReturnValue().SetUndefined();
    }
    else
    {
        info.GetReturnValue().Set(outBuff.ToLocalChecked());
    }
}

void NJSX509Certificate::IssueCertificate(const FunctionCallbackInfo<Value>& info)
{
    NJSX509Certificate* obj = nativeObjectFromJSObject(info);
    if( obj == nullptr )
    {
        return;
    }

    Isolate* isolate = info.GetIsolate();
    if( obj->x509Certificate_ == nullptr )
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Issue X509: incomplete CA certificate.")));
        return;
    }
    
    if( info.Length() == 0 )
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments.")));
        return;
    }
    
    String::Utf8Value cnameStr(info[0]->ToString());
    if( cnameStr.length() == 0 )
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "No string cname argument.")));
        return;
    }

    uint32_t serialNo = 1;
    EVP_PKEY* pk = nullptr;
    if( info.Length() > 1 )
    {
        serialNo = info[1]->Uint32Value();

        if( info.Length() > 2 )
        {
            ::std::string passphrase;
            if( info.Length() > 3 )
            {
                String::Utf8Value passStr(info[3]->ToString());
                if( passStr.length() > 0 )
                {
                    passphrase.append(*passStr, passStr.length());
                }
            }
            
            bool ok = CallWithRawDataRepresentation(info[2], [&passphrase, &pk, isolate](const char* pemData, size_t dataLength) -> bool {
                pk = newPrivateKeyFromPEM(pemData, dataLength, passphrase.c_str());
                if( pk == nullptr )
                {
                    std::string temp = "PrivateKey parse: ";
                    temp += ERR_error_string(ERR_get_error(), nullptr);
                    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, temp.c_str())));
                    return false;
                }
                return true;
            });
            if( !ok )
            {
                return;
            }
        }
    }
    
    if( pk == nullptr && obj->getPrivateKey() == nullptr )
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Issue X509: no private key.")));
        return;
    }
    
    X509* cert = obj->issueNewCertificate(*cnameStr, cnameStr.length(), serialNo, pk);
    if( cert == nullptr )
    {
        if( pk != nullptr )
        {
            EVP_PKEY_free(pk);
        }
        std::string temp = "Issue X509: ";
        temp += ERR_error_string(ERR_get_error(), nullptr);
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, temp.c_str())));
        return;
    }

    NJSX509Certificate* newObj = new NJSX509Certificate(cert);
    X509_free(cert);
    if( newObj == nullptr )
    {
        if( pk != nullptr )
        {
            EVP_PKEY_free(pk);
        }
        return;
    }

    newObj->setPrivateKey(pk);
    if( pk != nullptr )
    {
        EVP_PKEY_free(pk);
    }

    // Wrap native certificate object with JS object.
    MaybeLocal<Object> instance = NewJSInstance(isolate, 0, nullptr, newObj);
    if( instance.IsEmpty() )
    {
        delete newObj;
        info.GetReturnValue().SetUndefined();
        return;
    }

    info.GetReturnValue().Set(instance.ToLocalChecked());
}

void NJSX509Certificate::ExportCertificate(const FunctionCallbackInfo<Value>& info)
{
    NJSX509Certificate* obj = nativeObjectFromJSObject(info);
    if( obj == nullptr )
    {
        return;
    }
    
    Isolate* isolate = info.GetIsolate();
    if( obj->x509Certificate_ == nullptr )
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Export: incomplete certificate.")));
        return;
    }

    // Check the number of arguments passed and prepare certificate instantiation parameters.
    CertificateDataFormat certFormat = CertificateDataFormat::PEM;
    if( !CheckArguments(info, 0, -1, certFormat) )
    {
        return;
    }

    Local<Value> outCert;
    switch( certFormat ) {
        case CertificateDataFormat::PEM:
        {
            BIO* mbio = BIO_new(BIO_s_mem());
            if( mbio == nullptr )
            {
                break;
            }
            
            PEM_write_bio_X509(mbio, obj->x509Certificate_);
            BIO_write(mbio, "\0", 1);

            BUF_MEM* bufPtr;
            BIO_get_mem_ptr(mbio, &bufPtr);
            BIO_set_close(mbio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
            BIO_free(mbio);

            if( bufPtr != nullptr )
            {
                MemBIOBufferStringResource* retResource = new MemBIOBufferStringResource(bufPtr);
                assert(retResource != nullptr);
                if( retResource == nullptr )
                {
                    BUF_MEM_free(bufPtr);
                    break;
                }
                outCert = String::NewExternal(isolate, retResource);
            }
            break;
        }
        case CertificateDataFormat::DER:
        case CertificateDataFormat::Base64_DER:
        {
            int bufSize = i2d_X509(obj->x509Certificate_, NULL);
            if( bufSize <= 0 )
            {
                break;
            }
            char* buff = (char*)::malloc(bufSize);
            if( buff == nullptr )
            {
                break;
            }
            unsigned char* bufPtr = reinterpret_cast<unsigned char*>(buff);
            bufSize = i2d_X509(obj->x509Certificate_, &bufPtr);
            
            if( certFormat == CertificateDataFormat::DER )
            {
                auto outBuff = node::Buffer::New(isolate, buff, bufSize, [](char* data, void* hint) {
                    assert(data != nullptr);
                    ::free(data);
                }, nullptr);
                if( outBuff.IsEmpty() )
                {
                    ::free(buff);
                    break;
                }
                outCert = outBuff.ToLocalChecked();
                break;
            }
            
            BIO* mbio = BIO_new(BIO_s_mem());
            if( mbio == nullptr )
            {
                ::free(buff);
                break;
            }

            BIO* b64 = BIO_new(BIO_f_base64());
            if( b64 == nullptr )
            {
                BIO_free_all(mbio);
                ::free(buff);
                break;
            }
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
            mbio = BIO_push(b64, mbio);
            
            BIO_write(mbio, buff, bufSize);
            BIO_flush(mbio);

            ::free(buff);
            
            BUF_MEM* mbufPtr;
            BIO_get_mem_ptr(mbio, &mbufPtr);
            BIO_set_close(mbio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
            BIO_free_all(mbio);
            
            if( mbufPtr != nullptr )
            {
                MemBIOBufferStringResource* retResource = new MemBIOBufferStringResource(mbufPtr);
                assert(retResource != nullptr);
                if( retResource == nullptr )
                {
                    BUF_MEM_free(mbufPtr);
                    break;
                }
                outCert = String::NewExternal(isolate, retResource);
            }
            break;
        }
    }
    
    if( outCert.IsEmpty() )
    {
        info.GetReturnValue().SetUndefined();
    }
    else
    {
        info.GetReturnValue().Set(outCert);
    }
}

#if __clang__
#pragma mark - JS methods exported by NJSX509 module.
#endif

void NJSX509Certificate::ParseCertificateStore(const FunctionCallbackInfo<Value>& args)
{
    // Check the number of arguments passed and prepare certificate instantiation parameters.
    CertificateDataFormat certFormat = CertificateDataFormat::PEM;
    if( !CheckArguments(args, 1, 1, certFormat) )
    {
        return;
    }
    
    // Instantiate array of certificate objects.
    Isolate* isolate = args.GetIsolate();
    Local<Array> certArray = Array::New(isolate);
    
    // Try to populate array certificate objects.
    CallWithRawDataRepresentation(args[0], [&certArray, certFormat, isolate](const char* dataPtr, size_t dataLen) -> bool {
        uint32_t idx = 0;
        auto action = [&certArray, &idx, isolate](X509* c) -> void {
            NJSX509Certificate* obj = new NJSX509Certificate(c);
            if( obj == nullptr )
            {
                return;
            }
            
            // Wrap native certificate object with JS object.
            MaybeLocal<Object> instance = NewJSInstance(isolate, 0, nullptr, obj);
            if( instance.IsEmpty() )
            {
                delete obj;
                return;
            }
            certArray->Set(idx++, instance.ToLocalChecked());
        };
        
        switch( certFormat )
        {
            case CertificateDataFormat::PEM:
                return parseCertificateStorePEM(dataPtr, dataLen, action) > 0;
            case CertificateDataFormat::DER:
                return parseCertificateStoreDER(dataPtr, dataLen, action) > 0;
                break;
            case CertificateDataFormat::Base64_DER:
                return parseCertificateStoreBase64DER(dataPtr, dataLen, action) > 0;
        }
        return false;
    });
    
    args.GetReturnValue().Set(certArray);
}

void NJSX509Certificate::ParsePKCS12(const FunctionCallbackInfo<Value>& args)
{
    // Check the number of arguments passed and deduce input data format.
    CertificateDataFormat certFormat = CertificateDataFormat::PEM;
    if( !CheckArguments(args, 1, -1, certFormat) )
    {
        return;
    }

    // Define a passphrase for PKCS12 bag decryption.
    auto* isolate = args.GetIsolate();
    ::std::string passphrase;
    if( args.Length() > 1 )
    {
        String::Utf8Value passstring(args[1]->ToString());
        if( passstring.length() > 0 )
        {
            passphrase.append(*passstring, passstring.length());
        }
    }
    
    // Process PKCS12 data, provided to the parsing utility.
    Local<Object> retObj;
    auto dataProcessingCallback = [&retObj, &args, certFormat, &passphrase, isolate](const void* dataPtr, size_t dataLen) -> bool {
        NJSX509Certificate* cert = nullptr;
        
        // Handle primary certificate parsed out from PKCS12 blob.
        auto certCallback = [&retObj, &cert, isolate](X509* c) -> void {
            assert(cert == nullptr);
            cert = new NJSX509Certificate(c);
            assert(cert != nullptr);
            if( cert == nullptr )
            {
                return;
            }
            
            // Wrap native certificate object with JS object.
            MaybeLocal<Object> instance = NewJSInstance(isolate, 0, nullptr, cert);
            if( instance.IsEmpty() )
            {
                delete cert;
                return;
            }

            assert(retObj.IsEmpty());
            if( retObj.IsEmpty() )
            {
                retObj = Object::New(isolate);
            }
            
            retObj->Set(String::NewFromUtf8(isolate, "certificate"), instance.ToLocalChecked());
        };
        
        // Handle primary key parsed out from PKCS12 blob.
        auto pkCallback = [&retObj, &cert, &passphrase, isolate](EVP_PKEY* pk) -> void {
            if( cert != nullptr )
            {
                cert->setPrivateKey(pk);
            }
            copyPrivateKey(pk, passphrase.c_str(), passphrase.length(), [&retObj, isolate](BIO* mbio) {
                assert(mbio != nullptr);
                
                BUF_MEM* mbufPtr;
                BIO_get_mem_ptr(mbio, &mbufPtr);
                BIO_set_close(mbio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
                
                if( mbufPtr == nullptr )
                {
                    return;
                }
                
                MemBIOBufferStringResource* retResource = new MemBIOBufferStringResource(mbufPtr);
                assert(retResource != nullptr);
                if( retResource == nullptr )
                {
                    return;
                }
                
                if( retObj.IsEmpty() )
                {
                    retObj = Object::New(isolate);
                }
                retObj->Set(String::NewFromUtf8(isolate, "pk"), String::NewExternal(isolate, retResource));
            });
        };
        
        // Handle ancestor (CA) certificate(s) certificates parsed out from PKCS12 blob.
        int caCount = 0;
        Local<Array> caList;
        auto caCallback = [&retObj, &caList, &caCount, isolate](X509* c) -> void {
            auto* cert = new NJSX509Certificate(c);
            assert(cert != nullptr);
            if( cert == nullptr )
            {
                return;
            }
            
            // Wrap native certificate object with JS object.
            MaybeLocal<Object> instance = NewJSInstance(isolate, 0, nullptr, cert);
            if( instance.IsEmpty() )
            {
                delete cert;
                return;
            }

            if( caList.IsEmpty() )
            {
                caList = Array::New(isolate);
            }
            caList->Set(caCount++, instance.ToLocalChecked());
        };
        
        if( !parsePKCS12(dataPtr, dataLen, passphrase.c_str(), certCallback, pkCallback, caCallback) )
        {
            std::string temp = "PKCS12 parse: ";
            temp += ERR_error_string(ERR_get_error(), nullptr);
            isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, temp.c_str())));
            return false;
        }
        
        if( !caList.IsEmpty() )
        {
            if( retObj.IsEmpty() )
            {
                retObj = Object::New(isolate);
            }
            retObj->Set(String::NewFromUtf8(isolate, "ca"), caList);
        }
        return true;
    };
    
    bool rv;
    switch( certFormat )
    {
        case CertificateDataFormat::PEM:
        case CertificateDataFormat::Base64_DER:
            rv = CallWithBase64Decoder(args[0], dataProcessingCallback);
            break;
        case CertificateDataFormat::DER:
            rv = CallWithRawDataRepresentation(args[0], dataProcessingCallback);
            break;
    }
    
    if( !rv )
    {
        return;
    }
    
    if( retObj.IsEmpty() )
    {
        args.GetReturnValue().SetUndefined();
    }
    else
    {
        args.GetReturnValue().Set(retObj);
    }
}

#if __clang__
#pragma mark - NJSX509 Module declaration.
#endif

static void __NJSX509_init(Local<Object> exports)
{
    SSL_library_init();    
    SSL_load_error_strings();
    NJSX509Certificate::Init(exports);
}

NODE_MODULE(NJSX509, __NJSX509_init)
