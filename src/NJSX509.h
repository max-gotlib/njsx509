//
//  NJSX509.h
//  NJS51MapsProxy
//
//  Created by Maxim Gotlib on 2/28/17.
//  Copyright © 2017 Maxim Gotlib. All rights reserved.
//

#ifndef __NJSX509_h__
#define __NJSX509_h__

#if __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdocumentation"
#endif

#include <openssl/x509.h>
#include <openssl/pem.h>

#if !NDEBUG
#define X509_up_ref(X)      CRYPTO_add_lock(&((X)->references), 1, CRYPTO_LOCK_X509, __FILE__, __LINE__)
#define EVP_PKEY_up_ref(X)  CRYPTO_add_lock(&((X)->references), 1, CRYPTO_LOCK_EVP_PKEY, __FILE__, __LINE__)
#else
#define X509_up_ref(X)      CRYPTO_add_lock(&((X)->references), 1, CRYPTO_LOCK_X509, "NJS51Maps", __LINE__)
#define EVP_PKEY_up_ref(X)  CRYPTO_add_lock(&((X)->references), 1, CRYPTO_LOCK_EVP_PKEY, "NJS51Maps", __LINE__)
#endif

#define V8_DEPRECATION_WARNINGS 1

#include <node.h>
#include <node_object_wrap.h>
#include <node_buffer.h>

#if __clang__
#pragma clang diagnostic pop
#endif

namespace NJSX509
{
    using v8::FunctionCallbackInfo;
    using v8::PropertyCallbackInfo;
    using v8::Isolate;
    using v8::Local;
    using v8::MaybeLocal;
    using v8::Object;
    using v8::String;
    using v8::Date;
    using v8::Number;
    using v8::Array;
    using v8::Value;
    using v8::Function;
    using v8::Exception;
    using v8::FunctionTemplate;
    using v8::Context;
    using v8::Persistent;
    
    /**
     * Native X509 certificate wrapper class, backed by OpenSSL library.
     *
     * This class provides utility methods for parsing DER and PEM encoded X509 certificates and certificate stores.
     * Also, a set of accessor methods for X509 certificate components are provided.
     *
     * Instances of this class are wrapper within JS object, having NJSX509Certificate prototype function, exported by NJSX509 add-on module.
     *
     * JS NJSX509Certificate objects are instantiated by:
     *   const njsx509 = require('NJSX509');
     *   var cert = njsx509.NJSX509Certificate(data [, fmt])
     *   var cert = new njsx509.NJSX509Certificate(data [, fmt])
     *   Constructor parameters:
     *      data - X509 certificate data in one of supported formats, represented as a String or Node Buffer objet;
     *      fmt - (optional) certificate data representation format. Default format is 'pem'. Supported formats are:
     *          'pem' - PEM representation; data parameter may be String or Node.Buffer.
     *          'der' - DER representation; data parameter should be Node.Buffer.
     *          'der_base64' - Base-64 encoded DER representation; data parameter may be String or Node.Buffer.
     *      Return value: NJSX509Certificate object. Parsing error causes an exception and undefined value returned.
     *
     * JS NJSX509Certificate objects expose the following API:
     *
     *  NJSX509Certificate.subjectName
     *      String representation of certificate subject name.
     *
     *  NJSX509Certificate.issuer
     *      String representation of certificate issuer subject name.
     *
     *  NJSX509Certificate.commonName
     *      Certificate common name - string representation of CN component of the subject name.
     *
     *  NJSX509Certificate.validSince
     *      Date the certificate is valid from (inclusive).
     *
     *  NJSX509Certificate.notValidFrom
     *      Date the certificate is valid up to.
     *
     *  NJSX509Certificate.publicKey
     *      PEM representation for the certificate public key.
     *
     * Besides API, exposed by NJSX509Certificate objects, the NJSX509 add-on module export the following factory methods:
     *
     *  NJSX509Certificate.importCertificateStore(data [, fmt])
     *      data - Certificate store data in one of supported formats, represented as a String or Node Buffer objet;
     *      fmt - (optional) certificate data representation format. Default format is 'pem'. Supported formats are:
     *          'pem' - PEM representation - concatenation of PEM represented certificates; data parameter may be String or Node.Buffer.
     *          'der' - DER representation - concatenation of DER represented certificates; data parameter should be Node.Buffer.
     *          'der_base64' - Base-64 encoded DER representation; data parameter may be String or Node.Buffer.
     *      Return value: array of NJSX509Certificate objects. Parsing error causes an exception and undefined value returned.
     *
     *  NJSX509Certificate.importPKCS12(data [, fmt])
     */
    class NJSX509Certificate final : public node::ObjectWrap
    {
    public:
        
        /// Certificate data representation format type codes.
        typedef enum : int {
            /// PEM representation.
            PEM = 0,
            /// DER representation.
            DER,
            /// Base-64 encoded DER representation.
            Base64_DER
        } CertificateDataFormat;
        
    protected:  // Construction zone.
        
        /**
         * Designated (and the only) constructor for NJSX509Certificate class instances.
         *
         * @param cert OpenSSL wrapper for X509 certificate. Constructor up-references the wrapper, so it may be released (with X509_free() call) by the caller.
         */
        explicit NJSX509Certificate(X509* cert = nullptr);
        
        /**
         * Destructor for NJSX509Certificate class instances.
         */
        ~NJSX509Certificate();
        
        /// Forbidden default constructor.
        NJSX509Certificate() = delete;

        /// Forbidden copy constructor.
        NJSX509Certificate(const NJSX509Certificate&) = delete;

        /// Forbidden move constructor.
        NJSX509Certificate(const NJSX509Certificate&&) = delete;

        /// Forbidden assignment operator.
        NJSX509Certificate& operator = (const NJSX509Certificate&) = delete;
        
    public:     // X509 certificate parsing methods.
        
        /**
         * Parse single X509 certificate from PEM data.
         *
         * @param pemCertString X509 certificate data in PEM representation.
         * @param dataLength Size of certificate data (in bytes).
         * @return OpenSSL X509 certificate wrapper or null on error.
         */
        static X509* newCertificateFromPEM(const char* pemCertString, size_t dataLength);
        
        /**
         * Parse X509 certificate array from PEM data (certificate store). Each successfully parsed certificate (X509 structure pointer - as OpenSSL X509 certificate wrapper) is fed as the only argument to 'callback' call.
         *
         * @param pemCertString X509 certificate data in PEM representation.
         * @param dataLength Size of certificate data (in bytes).
         * @param callback Callback object to call with successfully parsed certificates. Callback should have the following semantics: void callback(X509* cert). The only callback argument is OpenSSL X509 certificate wrapper.
         * @return Numer of successfully parsed X509 certificates.
         */
        template <typename CertCallable>
        static int parseCertificateStorePEM(const char* pemCertString, size_t dataLength, CertCallable callback);
        
        /**
         * Parse single X509 certificate from DER data.
         *
         * @param derCertData X509 certificate data in DER representation.
         * @param dataLength Size of certificate data (in bytes).
         * @return OpenSSL X509 certificate wrapper or null on error.
         */
        static X509* newCertificateFromDER(const void* derCertData, size_t dataLength);
        
        /**
         * Parse single X509 certificate from DER data.
         *
         * @param bio X509 certificate data provider.
         * @return OpenSSL X509 certificate wrapper or null on error.
         */
        static X509* newCertificateFromDER(BIO* bio);

        /**
         * Parse single X509 certificate from Base-64 encoded DER data.
         *
         * @param base64DerCertData Base-64 encoded X509 certificate DER representation data.
         * @param dataLength Size of certificate data (in bytes).
         * @return OpenSSL X509 certificate wrapper or null on error.
         */
        static X509* newCertificateFromBase64DER(const char* base64DerCertData, size_t dataLength);
        
        /**
         * Parse single X509 certificate from DER data. On successful parsing, provided certificate data pointer and size are adjusted to point to the next certificate in the data chunk.
         *
         * @param derCertData X509 certificate data in DER representation.
         * @param dataSize Size of certificate data (in bytes).
         * @return OpenSSL X509 certificate wrapper or null on error.
         */
        static X509* newCertificateFromDERInc(const void*& derCertData, size_t& dataSize);
        
        /**
         * Parse X509 certificate array from DER data (concatenated DER-encoded certificate stream).
         *
         * @tparam CertCallable Callback type following semantics: void callback(X509* cert). The only callback argument is OpenSSL X509 certificate wrapper.
         * @param derCertData X509 certificate store data, consisting of concatenated DER certificate representations.
         * @param dataLength Size of certificate store data (in bytes).
         * @param callback Callback object to call with successfully parsed certificates.
         * @return Numer of successfully parsed X509 certificates.
         */
        template <typename CertCallable>
        static int parseCertificateStoreDER(const void* derCertData, size_t dataLength, CertCallable callback);
        
        /**
         * Parse X509 certicate array from Base-64 encoded DER data (concatenated DER-encoded certificate stream).
         *
         * @param base64DerCertData X509 certificate store data, consisting of concatenated DER certificate representations.
         * @param dataLength Size of certificate store data (in bytes).
         * @param callback Callback object to call with successfully parsed certificates. Callback should have the following semantics: void callback(X509* cert). The only callback argument is OpenSSL X509 certificate wrapper.
         * @return Number of successfully parsed X509 certificates.
         */
        template <typename CertCallable>
        static int parseCertificateStoreBase64DER(const char* base64DerCertData, size_t dataLength, CertCallable callback);
        
        /**
         * Parse PKCS12 bag into X509 certificate, private key and a list of ancestor X509 certificates.
         */
        
        /**
         * Parse Base-64 encoded PKCS12 bag into X509 certificate, private key and a list of ancestor X509 certificates.
         */
        
    public:     // X509 certificate attribute accessor methods.
        
        /**
         * Getter for string representation of X509 certificate subject name.
         *
         * @return String representation of X509 certificate subject name. NULL is returned on error.
         */
        const char* getSubject() const;

        /**
         * Getter for string representation of X509 certificate issuer subject name.
         *
         * @return String representation of X509 certificate issuer subject name. NULL is returned on error.
         */
        const char* getIssuer() const;
        
        /**
         * Getter for CN (common name component) of string representation of X509 certificate subject name.
         *
         * @return CN component of X509 certificate subject name. NULL is returned on error.
         */
        const char* getCommonName() const;

        /**
         * Get X509 certificate validity start date.
         *
         * @return Certificate validity start date as Unix time. 0 is returned on error.
         */
        time_t getValidFrom() const;

        /**
         * Get X509 certificate validity end date.
         *
         * @return Certificate validity end date as Unix time. 0 is returned on error.
         */
        time_t getNotValidAfter() const;
        
        /**
         * Compose PEM encoded RSA public key, represented by a zero-terminated string, and feed it to caller supplied callback.
         *
         * @tparam StringCallable Callback prototype: void callback(const char* pkData, size_t pkLen).
         * @param callback Callback callable to feed with public key PEM representation data.
         * @return True on successfully composed public key representation.
         */
        template <typename StringCallable>
        bool copyPublicKey(StringCallable callback) const;
        
    protected:  // Helper (utility) methods.
        
        /**
         * Helper method for presented JS value as raw data and feed it to a caller supplied functor.
         * Provided JS value should be a String or convertible to String object (in that case it's UTF-8 representation is used), either Node.Buffer object.
         *
         * @tparam CallableWithRawData Raw data callback prototype, having the following semantics: void callback(const void* data, size_t size).
         * @param val JS value, whose raw data representation should be fed to a functor.
         * @param callback Functor to call with raw data representation for given JS value.
         * @return True on successfully
         */
        template <typename CallableWithRawData>
        static bool CallWithRawDataRepresentation(Local<Value> val, CallableWithRawData callback);
        
        /**
         * Helper method for checking the number of function arguments passed and guessing requested certificate data format.
         * This method throws JS exception, if argument list constrains aren't satisfied for the function.
         *
         * @param args Function argument list.
         * @param minNumberOfArguments Minimum number of arguments, expected by the function.
         * @param typeArgumentIndex Index of the data type function argument.
         * @param certFormat On return, is assigned with guessed data type code.
         * @return True, if argument list constrains are satisfied for the function.
         */
        static bool CheckArguments(const FunctionCallbackInfo<Value>& args, int minNumberOfArguments, int typeArgumentIndex, CertificateDataFormat& certFormat);

        /**
         * Helper method for instantiating JS object with NJSX509Certificate prototype.
         *
         * @param isolate Isolated instance of the V8 engine for new JS object.
         * @param argc Constructor function argument count.
         * @param argv Constructor function argument array.
         * @return JS object instance with NJSX509Certificate prototype.
         */
        static MaybeLocal<Object> NewJSInstance(Isolate* isolate, unsigned argc = 0, Local<Value> argv[] = nullptr);

        /**
         * Helper method for instantiating JS object with NJSX509Certificate prototype. Prepares argument list, calls NewJSInstance() and packs result into constructor function parameter list info.
         * Throws JS exception on too many arguments, passed to constructor function.
         * Should be the last method called by caller before yielding control to V8 engine.
         *
         * @param args Constructor function parameter list info.
         */
        static void NewInstance(const FunctionCallbackInfo<Value>& args);
        
        /**
         * Helper method for unwrapping native (C++) instance, given a JS object referenced as a method/accessor/callback calling context.
         *
         * @tparam MethodCallInfo Method call parameter info type. Should be one of FunctionCallbackInfo or PropertyCallbackInfo.
         * @param info Method parameter call info.
         * @return NJSX509Certificate class instance, unwrapped from method parameter call info.
         */
        template <class MethodCallInfo>
        static NJSX509Certificate* nativeObjectFromJSObject(const MethodCallInfo& info);
        
    public:     // JS wrapper object initialization and instantiation methods.

        /**
         * Instantiate and persist constructor function object for NJSX509Certificate class.
         * Export NodeJS add-on methods.
         * This method is intended to be called during V8 add-on initialization.
         *
         * @param exports Node JS add-on object to export constructor function and method.
         */
        static void Init(Local<Object> exports);
        
    protected:  // JS object property accessors and methods.
        
        /**
         * Implementation for constructor function for NJSX509Certificate JS class.
         * Instantiates native (C++) NJSX509Certificate class instance with caller supplied arguments.
         * Wraps native class instance with JS object, that is set as the function calling context.
         *
         * @param args JS function parameter list info.
         */
        static void New(const FunctionCallbackInfo<Value>& args);
        
        /**
         * Accessor function implementation for 'subjectName' property of NJSX509Certificate JS prototype object.
         * Property value is acquired from the native (C++) instance, wrapped by JS object that is set as accessor function calling context.
         *
         * @param property JS object property name (ignored, because this method serves only one property).
         * @param info JS accessor function parameter list info.
         */
        static void SubjectName(Local<String> property, const PropertyCallbackInfo<Value>& info);
        
        /**
         * Accessor function implementation for 'commonName' property of NJSX509Certificate JS prototype object.
         * Property value is acquired from the native (C++) instance, wrapped by JS object that is set as accessor function calling context.
         *
         * @param property JS object property name (ignored, because this method serves only one property).
         * @param info JS accessor function parameter list info.
         */
        static void CommonName(Local<String> property, const PropertyCallbackInfo<Value>& info);
        
        /**
         * Accessor function implementation for 'issuer' property of NJSX509Certificate JS prototype object.
         * Property value is acquired from the native (C++) instance, wrapped by JS object that is set as accessor function calling context.
         *
         * @param property JS object property name (ignored, because this method serves only one property).
         * @param info JS accessor function parameter list info.
         */
        static void Issuer(Local<String> property, const PropertyCallbackInfo<Value>& info);
        
        /**
         * Accessor function implementation for 'validSince' property of NJSX509Certificate JS prototype object.
         * Property value is acquired from the native (C++) instance, wrapped by JS object that is set as accessor function calling context.
         *
         * @param property JS object property name (ignored, because this method serves only one property).
         * @param info JS accessor function parameter list info.
         */
        static void ValidSince(Local<String> property, const PropertyCallbackInfo<Value>& info);
        
        /**
         * Accessor function implementation for 'notValidFrom' property of NJSX509Certificate JS prototype object.
         * Property value is acquired from the native (C++) instance, wrapped by JS object that is set as accessor function calling context.
         *
         * @param property JS object property name (ignored, because this method serves only one property).
         * @param info JS accessor function parameter list info.
         */
        static void NotValidAfter(Local<String> property, const PropertyCallbackInfo<Value>& info);
        
        /**
         * Accessor function implementation for 'publicKey' property of NJSX509Certificate JS prototype object.
         * Property value is acquired from the native (C++) instance, wrapped by JS object that is set as accessor function calling context.
         *
         * @param property JS object property name (ignored, because this method serves only one property).
         * @param info JS accessor function parameter list info.
         */
        static void PublicKey(Local<String> property, const PropertyCallbackInfo<Value>& info);

    protected:  // NodeJS add-on exported methods.
        
        static void ParseCertificateStore(const FunctionCallbackInfo<Value>& args);
        
        static void ParsePKCS12(const FunctionCallbackInfo<Value>& args);
        
        static void IssueCertificate(const FunctionCallbackInfo<Value>& args);
        
    private:
        
        /// Persistent instance of constructor function for NJSX509Certificate JS class.
        static Persistent<Function> constructor_;
        
        /// Underlying native certificate instance.
        X509* x509Certificate_;
        
        /// Certificate subject name, represented by a single line zero-terminated string.
        mutable char* subject_;

        /// Certificate issuer  name, represented by a single line zero-terminated string.
        mutable char* issuer_;

        /// Common name component of the certificate subject name, represented by a zero-terminated string.
        mutable char* commonName_;
    };
    
}  // end of namespace NJSX509

// Pick up template methods implementation.
#include "NJSX509.hpp"

#endif /* __NJSX509_h__ */
