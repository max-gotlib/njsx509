//
//  NJSX509.hpp
//  NJS51MapsProxy
//
//  Created by Maxim Gotlib on 2/28/17.
//  Copyright © 2017 Maxim Gotlib. All rights reserved.
//

#ifndef __NJSX509_hpp__
#define __NJSX509_hpp__

#include "NJSX509.h"

namespace NJSX509 {

    template <typename CallableWithRawData>
    bool NJSX509Certificate::CallWithRawDataRepresentation(Local<Value> val, CallableWithRawData callback)
    {
        if( val.IsEmpty() )
        {
            return false;
        }
        
        if( node::Buffer::HasInstance(val) )
        {
            const char* dataPtr = node::Buffer::Data(val);
            size_t dataLen = node::Buffer::Length(val);
            if( dataPtr != nullptr || dataLen )
            {
                callback(dataPtr, dataLen);
                return true;
            }
        }
        
        String::Utf8Value utf8Val(val);
        if( utf8Val.length() > 0 )
        {
            callback(*utf8Val, utf8Val.length());
            return true;
        }
        
        return false;
    }

    template <class MethodCallInfo>
    NJSX509Certificate* NJSX509Certificate::nativeObjectFromJSObject(const MethodCallInfo& info)
    {
        Local<Object> _self = info.Holder();
        if( _self.IsEmpty() )
        {
            Isolate* isolate = info.GetIsolate();
            assert(isolate != nullptr);
            if( isolate != nullptr )
            {
                isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "No object")));
            }
            return nullptr;
        }
        
        NJSX509Certificate* obj = ObjectWrap::Unwrap<NJSX509Certificate>(_self);
        assert(obj != nullptr);
        return obj;
    }
    
    template <const char* (NJSX509Certificate::*method)() const>
    void NJSX509Certificate::stringPropertyAccessor(Local<String> __unused property, const PropertyCallbackInfo<Value>& info)
    {
        NJSX509Certificate* obj = nativeObjectFromJSObject(info);
        if( obj == nullptr )
        {
            return;
        }
        
        const char* val = (obj->*method)();
        
        if( val != nullptr )
        {
            info.GetReturnValue().Set(String::NewFromUtf8(info.GetIsolate(), val));
        }
        else
        {
            info.GetReturnValue().SetUndefined();
        }
    }
    
    template <time_t (NJSX509Certificate::*method)() const>
    void NJSX509Certificate::datePropertyAccessor(Local<String> __unused property, const PropertyCallbackInfo<Value>& info)
    {
        NJSX509Certificate* obj = nativeObjectFromJSObject(info);
        if( obj == nullptr )
        {
            return;
        }
        
        time_t val = (obj->*method)();
        
        if( val != 0 )
        {
            info.GetReturnValue().Set(Date::New(info.GetIsolate(), val * 1000.0));
        }
        else
        {
            info.GetReturnValue().SetUndefined();
        }
    }

    template <typename CertCallable>
    int NJSX509Certificate::parseCertificateStorePEM(const char* pemCertString, size_t dataLength, CertCallable callback)
    {
        assert(pemCertString != nullptr);
        assert(dataLength > 0);
        if( pemCertString == nullptr || dataLength == 0 )
        {
            return 0;
        }
        BIO* bio = BIO_new_mem_buf((void*)pemCertString, static_cast<int>(dataLength));
        assert(bio != nullptr);
        if( bio == nullptr )
        {
            return 0;
        }
        
        int count = 0;
        while( !BIO_eof(bio) )
        {
            X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
            if( cert == nullptr )
            {
                break;
            }
            callback(cert);
            X509_free(cert);
            count++;
        }
        
        BIO_free(bio);
        return count;
    }

    template <typename CertCallable>
    int NJSX509Certificate::parseCertificateStoreDER(const void* derCertData, size_t dataSize, CertCallable callback)
    {
        assert(derCertData != nullptr);
        assert(dataSize > 0);
        if( derCertData == nullptr || dataSize == 0 )
        {
            return 0;
        }
        
        int count = 0;
        while( dataSize > 0 )
        {
            X509* cert = newCertificateFromDERInc(derCertData, dataSize);
            if( cert == nullptr )
            {
                break;
            }
            callback(cert);
            X509_free(cert);
            count++;
        }
        return count;
    }

    template <typename CertCallable>
    int NJSX509Certificate::parseCertificateStoreBase64DER(const char* derCertData, size_t dataSize, CertCallable callback)
    {
        assert(derCertData != nullptr);
        assert(dataSize > 0);
        if( derCertData == nullptr || dataSize == 0 )
        {
            return 0;
        }
        
        BIO* b64 = BIO_new(BIO_f_base64());
        assert(b64 != nullptr);
        if( b64 == nullptr )
        {
            return 0;
        }
        
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO* bmem = BIO_new_mem_buf(const_cast<char*>(derCertData), static_cast<int>(dataSize));
        assert(bmem != nullptr);
        if( bmem == nullptr )
        {
            BIO_free(b64);
            return 0;
        }
        bmem = BIO_push(b64, bmem);
        
        int count = 0;
        while( !BIO_eof(bmem) )
        {
            X509* cert = newCertificateFromDER(bmem);
            if( cert == nullptr )
            {
                break;
            }
            callback(cert);
            X509_free(cert);
            count++;
        }
        
        BIO_free_all(bmem);
        return count;
    }

    template <typename StringCallable>
    bool NJSX509Certificate::copyPublicKey(StringCallable callback) const
    {
        if( x509Certificate_ == nullptr )
        {
            return false;
        }
        
        EVP_PKEY* pk = X509_get_pubkey(x509Certificate_);
        if( pk == nullptr )
        {
            return false;
        }
        
        BIO* mbio = BIO_new(BIO_s_mem());
        if( mbio == nullptr )
        {
            EVP_PKEY_free(pk);
            return false;
        }
        
        PEM_write_bio_PUBKEY(mbio, pk);
        EVP_PKEY_free(pk);
        BIO_write(mbio, "\0", 1);
        
        const char* pkPtr = nullptr;
        size_t pkLen = BIO_get_mem_data(mbio, &pkPtr);
        callback(pkPtr, pkLen);

        BIO_free(mbio);
        return true;
    }

} // en of namespace NJS51Maps

#endif /* __NJSX509_hpp__ */
