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
#include <openssl/buffer.h>

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
     *  NJSX509Certificate.getPrivateKey([passphrase])
     *    Get a private key, associated with certificate, encrypt it with given passphrase and return in PEM (encrypted PKCS8 blob) format.
     *    Parameters:
     *      passphrase - Passphrase to encrypt private key with. Should be a convertible to String. Default to an empty string.
     *    Return value: PEM-encoded private key string (encrypted PKCS8 blob). Undefined is returned if there is no private key, associated with certificate object.
     *
     *  NJSX509Certificate.setPrivateKey(key [, passphrase])
     *    Associate a private key with certificate, Private key should be provided as PEM string (encrypted PKCS8 blob), with optional passphrase for decrypting.
     *    Parameters:
     *      key - PEM-encoded private key string (encrypted PKCS8 blob). Should be a convertible to String or Node.Buffer.
     *      passphrase - Passphrase to encrypt private key with. Should be a convertible to String. Default to an empty string.
     *    Return value: PEM-encoded private key string. Undefined is returned if there is no private key, associated with certificate object.
     *
     *  NJSX509Certificate.encryptPublic(data [, padding])
     *    Encrypt data with certificate public key.
     *    Parameters:
     *      data - Input data to encrypt. Should be a convertible to String (considered to be 'utf8' encoded string) or Node.Buffer.
     *      padding - (optional) Padding to use for encrypted data. Supported padding algorithms are: NO (no padding), PKCS1, SSLV23, OAEP, X931, PKCS1_PSS.
     *    Return value: Node.Buffer with encrypted data. Undefined is returned on error. Incomplete or invalid input data causes JS exception thrown.
     *
     *  NJSX509Certificate.encryptPublic(data [, padding])
     *    Decrypt data with private key, associated with certificate.
     *    Parameters:
     *      data - Input data to decrypt. Should be a convertible to String (considered to be 'utf8' encoded string) or Node.Buffer.
     *      padding - (optional) Padding, used for decrypted data. Supported padding algorithms are: NO (no padding), PKCS1, SSLV23, OAEP, X931, PKCS1_PSS.
     *    Return value: Node.Buffer with decrypted data. Undefined is returned on error. Incomplete or invalid input data causes JS exception thrown.
     *
     *  NJSX509Certificate.issueCertificate(cname [, serialNo [, key [, passphrase]]])
     *    Issue new X509 certificate. Instance should have a private key attached, either it should be explicitly provided as PEM string (encrypted PKCS8 blob), with optional passphrase for decrypting.
     *    Parameters:
     *      cname - Common name for new certificate. Should be a convertible to String.
     *      serialNo - (optional) Serial number for the new certificate. Should be a convertible to Number. Defaults to 1.
     *      key - (optional) PEM-encoded private key string (encrypted PKCS8 blob). Should be a convertible to String or Node.Buffer. If not passed, then private key, associated with issuer certificate is used.
     *      passphrase - (optional) Passphrase to encrypt private key with. Should be a convertible to String. Default to an empty string.
     *    Return value: A new issued certificate - NJSX509Certificate class instance. Undefined is returned on error. Incomplete or invalid input data causes JS exception thrown.
     *
     *  NJSX509Certificate.exportCertificate([fmt])
     *    Export X509 certificate DER/PEM/Base64 format.
     *    Parameters:
     *      fmt - (optional) certificate data representation format. Default format is 'pem'. Supported formats are:
     *          'pem' - PEM representation;
     *          'der' - DER representation;
     *          'der_base64' - Base-64 encoded DER representation.
     *    Return value: String (for 'pem' and 'base64_der' formats) or Node.Buffer instance (for 'der'). Undefined is returned on error. Incomplete or invalid input data causes JS exception thrown.
     *
     * Besides API, exposed by NJSX509Certificate objects, the NJSX509 add-on module export the following factory methods:
     *
     *  NJSX509.importCertificateStore(data [, fmt])
     *    Parse a certificate store and compose an array of certificate objects.
     *    Parameters:
     *      data - Certificate store data in one of supported formats, represented as a String or Node Buffer objet;
     *      fmt - (optional) certificate data representation format. Default format is 'pem'. Supported formats are:
     *          'pem' - PEM representation - concatenation of PEM represented certificates; data parameter may be String or Node.Buffer.
     *          'der' - DER representation - concatenation of DER represented certificates; data parameter should be Node.Buffer.
     *          'der_base64' - Base-64 encoded DER representation; data parameter may be String or Node.Buffer.
     *    Return value: array of NJSX509Certificate objects. Parsing error causes an exception and undefined value returned.
     *
     *  NJSX509.importPKCS12(data [, passphrase ] [, fmt ])
     *    Parse PKCS12 (client certificate) data blob into a primary (client) certificate, associated with a private key, and a list of ancestor (CA) certificates.
     *    Parameters:
     *      data - Certificate store data in one of supported formats, represented as a String or Node Buffer objet;
     *      passphrase - (optional) Passphrase for PKCS12 bag decryption. Defaults to an empty string;
     *      fmt - (optional, always the last parameter) certificate data representation format. Default format is 'pem'. Supported formats are:
     *          'pem' - PEM representation - concatenation of PEM represented certificates; data parameter may be String or Node.Buffer.
     *          'der' - DER representation - concatenation of DER represented certificates; data parameter should be Node.Buffer.
     *          'der_base64' - Base-64 encoded DER representation; data parameter may be String or Node.Buffer.
     *    Return value by JS method is a JS object with the following properties:
     *      'certificate' - Primary (client) certificate object. If there was a private key in input data bad, then it is associated with primary certificate.
     *      'pk' - Private key in PEM format, encrypted with the same passphrase, that was used to decrypt PKCS12 bag.
     *      'ca' - An array of NJSX509Certificate objects, representing ancestor certificates.
     *    Parsing error causes a JS exception thrown and undefined value returned.
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
         * @param privateKey OpenSSL wrapper for a private key. Constructor up-references the wrapper, so it may be released (with EVP_PKEY_free() call) by the caller.
         */
        explicit NJSX509Certificate(X509* cert = nullptr, EVP_PKEY* privateKey = nullptr);
        
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
         * @note The caller takes a responsibility to release returned certificate.
         */
        static X509* newCertificateFromPEM(const char* pemCertString, size_t dataLength);
        
        /**
         * Parse X509 certificate array from PEM data (certificate store). Each successfully parsed certificate (X509 structure pointer - as OpenSSL X509 certificate wrapper) is fed as the only argument to 'callback' call.
         *
         * @tparam CertCallable Callback type for certificate following semantics: void callback(X509* cert). The only callback argument is OpenSSL X509 certificate wrapper.
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
         *
         * @note The caller takes a responsibility to release returned certificate.
         */
        static X509* newCertificateFromDER(const void* derCertData, size_t dataLength);
        
        /**
         * Parse single X509 certificate from DER data.
         *
         * @param bio X509 certificate data provider.
         * @return OpenSSL X509 certificate wrapper or null on error.
         *
         * @note The caller takes a responsibility to release returned certificate.
         */
        static X509* newCertificateFromDER(BIO* bio);

        /**
         * Parse single X509 certificate from Base-64 encoded DER data.
         *
         * @param base64DerCertData Base-64 encoded X509 certificate DER representation data.
         * @param dataLength Size of certificate data (in bytes).
         * @return OpenSSL X509 certificate wrapper or null on error.
         *
         * @note The caller takes a responsibility to release returned certificate.
         */
        static X509* newCertificateFromBase64DER(const char* base64DerCertData, size_t dataLength);
        
        /**
         * Parse single X509 certificate from DER data. On successful parsing, provided certificate data pointer and size are adjusted to point to the next certificate in the data chunk.
         *
         * @param derCertData X509 certificate data in DER representation.
         * @param dataSize Size of certificate data (in bytes).
         * @return OpenSSL X509 certificate wrapper or null on error.
         *
         * @note The caller takes a responsibility to release returned certificate.
         */
        static X509* newCertificateFromDERInc(const void*& derCertData, size_t& dataSize);
        
        /**
         * Parse X509 certificate array from DER data (concatenated DER-encoded certificate stream).
         *
         * @tparam CertCallable Callback type following semantics: void callback(X509* cert). The only callback argument is OpenSSL X509 certificate wrapper.
         *
         * @param derCertData X509 certificate store data, consisting of concatenated DER certificate representations.
         * @param dataLength Size of certificate store data (in bytes).
         * @param callback Callback object to call with successfully parsed certificates.
         * @return Number of successfully parsed X509 certificates.
         */
        template <typename CertCallable>
        static int parseCertificateStoreDER(const void* derCertData, size_t dataLength, CertCallable callback);
        
        /**
         * Parse X509 certicate array from Base-64 encoded DER data (concatenated DER-encoded certificate stream).
         *
         * @tparam CertCallable Callback type following semantics: void callback(X509* cert). The only callback argument is OpenSSL X509 certificate wrapper.
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
         *
         * @tparam CertCallable Callback type for primary (client) certificate following semantics: void callback(X509* cert). The only callback argument is OpenSSL X509 certificate wrapper.
         * @tparam PrivateKeyCallable Callback type for private key following semantics: void callback(EVP_PKEY* key). The only callback argument is OpenSSL primary key wrapper.
         * @tparam CACertCallable Callback type for ancestor (CA) certificates following semantics: void callback(X509* cert). The only callback argument is OpenSSL X509 certificate wrapper.
         *
         * @param pkcs12Data PKCS12 blob data (DER).
         * @param dataLength Size of (in bytes) of PKCS12 data blob.
         * @param passphrase Passphrase for decrypting PKCS12 secure bag.
         * @param certCallback Callback, fed with primary certificate.
         * @param pkCallback Callback, fed with private key.
         * @param caCallback Callback, fed with secondary (ancestor) certificates (one call per each certificate).
         *
         * @note It guaranteed, that if given PKCS12 bag has a certificate definition, then certCallback is called first (before other callbacks).
         * @note Certificate, private key and CA certificates, presented via callbacks, are released upon function return.
         */
        template <typename CertCallable, typename PrivateKeyCallable, typename CACertCallable>
        static bool parsePKCS12(const void* pkcs12Data, size_t dataLength, const char* passphrase, CertCallable certCallback, PrivateKeyCallable pkCallback, CACertCallable caCallback);

        /**
         * Parse PEM encoded (encrypted PKCS8 data blob) private key.
         *
         * @param pemPKString PEM encoded private key data.
         * @param dataLength Size of PEM encoded private key data.
         * @param passphrase Passphrase for private key decryption. If passed as null, default to an empty string.
         * @return OpenSSL EVP_PKEY wrapper for private key or null on error.
         *
         * @note The caller takes a responsibility to release returned key.
         */
        static EVP_PKEY* newPrivateKeyFromPEM(const char* pemPKString, size_t dataLength, const char* passphrase);

        /**
         * Parse PEM encoded (encrypted PKCS8 data blob) private key.
         *
         * @param pkBio Data provider for PEM encoded private key.
         * @param passphrase Passphrase for private key decryption. If passed as null, default to an empty string.
         * @return OpenSSL EVP_PKEY wrapper for private key or null on error.
         *
         * @note The caller takes a responsibility to release returned key.
         */
        static EVP_PKEY* newPrivateKeyFromPEM(BIO* pkBio, const char* passphrase);
        
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
        
        /**
         * Compose PEM encoded RSA private key, encrypted with given passphrase, represented by a zero-terminated string and feed it to caller supplied callback.
         *
         * @tparam StringCallable Callback prototype: void callback(const char* pkData, size_t pkLen).
         * @param passphrase Passphrase for private key encryption.
         * @param passphraseLength Length (in bytes) of the passphrase.
         * @param callback Callback callable to feed with encrypted private key PEM representation data.
         * @return True on successfully composed private key representation.
         */
        template <typename StringCallable>
        static bool copyPrivateKey(EVP_PKEY* privateKey, const char* passphrase, size_t passphraseLength, StringCallable callback);
        
        /**
         * Getter for private key attribute of the certificate.
         *
         * @return Private key OpenSSL wrapper or null if no private key was defined.
         */
        inline EVP_PKEY* getPrivateKey() const
        {
            return privateKey_;
        }
        
        /**
         * Define private key attribute to the certificate.
         * 
         * @param pk Private key OpenSSL wrapper. This method up-refs the pk wrapper, so it may be released by the caller right after return.
         */
        void setPrivateKey(EVP_PKEY* pk);
        
        /**
         * Encrypt data blob with certificate public key.
         *
         * @param inData Input data blob to encrypt.
         * @param inSize Size of input data blob (in bytes).
         * @param outData Buffer with pointer to output (encrypted) data. On return, this pointer us set to allocated memory block, containing output data.
         * @param padding Padding to use for encryption.
         * @return Size of output data block, allocated and assigned to *outData. Zero is returned on error.
         *
         * @note The caller is responsible for deallocating returned data.
         * @note Maximum data block size is: RSA_key_size/8 - 2 * Hash_size - Padding_size. Hash_size is 20 for SHA-1. Padding_size is 11 for PKCS (v1.5) and is 2 for OAEP.
         */
        size_t encryptPublic(const void* inData, size_t inSize, void** outData, int padding = RSA_PKCS1_PADDING);

        /**
         * Decrypt data blob with private key, associated with certificate.
         *
         * @param inData Input data blob to decrypt.
         * @param inSize Size of input data blob (in bytes).
         * @param outData Buffer with pointer to output (decrypted) data. On return, this pointer us set to allocated memory block, containing output data.
         * @param padding Padding to use for decryption.
         * @return Size of output data block, allocated and assigned to *outData. Zero is returned on error.
         *
         * @note The caller is responsible for deallocating returned data.
         * @note Maximum data block size is: RSA_key_size/8 - 2 * Hash_size - Padding_size. Hash_size is 20 for SHA-1. Padding_size is 11 for PKCS (v1.5) and is 2 for OAEP.
         */
        size_t decryptPrivate(const void* inData, size_t inSize, void** outData, int padding = RSA_PKCS1_PADDING);
        
        /**
         * Issue a X509 certificate, signed by the given client identity.
         *
         * @param cname Common name part of the issued certificate subject name.
         * @param serialNo Serial number attribute for the issued certificate.
         * @param privateKey Private key for the issued certificate. If NULL is passed, then issued certificate will have the same private key as the source identity.
         * @return Issued X509 opaque reference. The caller is expected to release the issued certificate.
         */
        X509* issueNewCertificate(const char* cname, size_t cnameLen, unsigned serialNo = 1, EVP_PKEY* privateKey = nullptr);

    protected:  // Helper (utility) methods.
        
        /**
         * Helper method for presented JS value as raw data and feed it to a caller supplied functor.
         * Provided JS value should be a String or convertible to String object (in that case it's UTF-8 representation is used), either Node.Buffer object.
         * Provided value content is expected to be UTF-8 string representing Base-64 encoded data blob.
         *
         * @tparam CallableWithRawData Raw data callback prototype, having the following semantics: bool callback(const void* data, size_t size).
         *
         * @param val JS value, whose raw data representation should be fed to a functor.
         * @param callback Functor to call with raw data representation for given JS value.
         * @return True on successfully
         */
        template <typename CallableWithRawData>
        static bool CallWithBase64Decoder(Local<Value> val, CallableWithRawData callback);
        
        /**
         * Helper method for presented JS value as raw data and feed it to a caller supplied functor.
         * Provided JS value should be a String or convertible to String object (in that case it's UTF-8 representation is used), either Node.Buffer object.
         *
         * @tparam CallableWithRawData Raw data callback prototype, having the following semantics: bool callback(const void* data, size_t size).
         *
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
         * @param typeArgumentIndex Index of the data type function argument. If negative integer passed, then type argument is considered to be the last one.
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
         * @param wrappedObject Native (C++) object pointer to wrap within JS object.
         * @return JS object instance with NJSX509Certificate prototype.
         */
        static MaybeLocal<Object> NewJSInstance(Isolate* isolate, unsigned argc = 0, Local<Value> argv[] = nullptr, NJSX509Certificate* wrappedObject = nullptr);

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
         * Accessor function implementation for string-type properties of NJSX509Certificate JS prototype object.
         * Property value is acquired from the native (C++) instance, wrapped by JS object that is set as accessor function calling context.
         *
         * @tparam method Accessor method, called on native NJSX509Certificate class instance to get property value.
         * @param property JS object property name (ignored, because this method serves only one property).
         * @param info JS accessor function parameter list info.
         */
        template <const char* (NJSX509Certificate::*method)() const>
        static void stringPropertyAccessor(Local<String> __unused property, const PropertyCallbackInfo<Value>& info);
        
        /**
         * Accessor function implementation for date-typed properties of NJSX509Certificate JS prototype object.
         * Property value is acquired from the native (C++) instance, wrapped by JS object that is set as accessor function calling context.
         *
         * @tparam method Accessor method, called on native NJSX509Certificate class instance to get property value.
         * @param property JS object property name (ignored, because this method serves only one property).
         * @param info JS accessor function parameter list info.
         */
        template <time_t (NJSX509Certificate::*method)() const>
        static void datePropertyAccessor(Local<String> __unused property, const PropertyCallbackInfo<Value>& info);
        
        /**
         * Accessor function implementation for 'publicKey' property of NJSX509Certificate JS prototype object.
         * Property value is acquired from the native (C++) instance, wrapped by JS object that is set as accessor function calling context.
         *
         * @param property JS object property name (ignored, because this method serves only one property).
         * @param info JS accessor function parameter list info.
         */
        static void PublicKey(Local<String> property, const PropertyCallbackInfo<Value>& info);
        
        /**
         * JS object of NJSX509Certificate class exported method for encrypting and PEM encoding private key.
         * It is expected, that JS method will be called with an optional (defaults to an empty string) argument - private key encryption passphrase.
         * Return value by JS method is a string with encrypted and PEM private key.
         *
         * @param info JS function parameter list info.
         */
        static void GetPrivateKey(const FunctionCallbackInfo<Value>& info);
        
        /**
         * JS object of NJSX509Certificate class exported method for associating a private key with certificate. Private key should be provided as PEM string (encrypted PKCS8 blob), with optional passphrase for decrypting.
         * It is expected, that JS method will be called with the following parameters:
         *      key - PEM-encoded private key string (encrypted PKCS8 blob). Should be a convertible to String or Node.Buffer.
         *      passphrase - Passphrase to encrypt private key with. Should be a convertible to String. Default to an empty string.
         * Return value by JS method is a bool, indicating successful operation completion. Incomplete or invalid input data causes JS exception thrown.
         *
         * @param info JS function parameter list info.
         */
        static void SetPrivateKey(const FunctionCallbackInfo<Value>& info);

        /**
         * JS object of NJSX509Certificate class exported method for data encryption with certificate public key.
         * It is expected, that JS method will be called with the following parameters:
         *      data - Input data to encrypt. Should be a convertible to String (considered to be 'utf8' encoded string) or Node.Buffer.
         *      padding - (optional) Padding to use for encrypted data. Supported padding algorithms are: NO (no padding), PKCS1, SSLV23, OAEP, X931, PKCS1_PSS.
         * Return value by JS method is a Node.Buffer with encrypted data. Undefined is returned on error. Incomplete or invalid input data causes JS exception thrown.
         *
         * @param info JS function parameter list info.
         */
        static void EncryptWithPublicKey(const FunctionCallbackInfo<Value>& info);

        /**
         * JS object of NJSX509Certificate class exported method for data decryption with private key, associated with certificate.
         * It is expected, that JS method will be called with the following parameters:
         *      data - Input data to decrypt. Should be a convertible to String (considered to be 'utf8' encoded string) or Node.Buffer.
         *      padding - (optional) Padding, used for decrypted data. Supported padding algorithms are: NO (no padding), PKCS1, SSLV23, OAEP, X931, PKCS1_PSS.
         * Return value by JS method is a Node.Buffer with decrypted data. Undefined is returned on error. Incomplete or invalid input data causes JS exception thrown.
         *
         * @param info JS function parameter list info.
         */
        static void DecryptWithPrivateKey(const FunctionCallbackInfo<Value>& info);

        /**
         * JS object of NJSX509Certificate class exported method for X509 certificate issuing. Instance should have a private key attached, either it should be provided as PEM string (encrypted PKCS8 blob), with optional passphrase for decrypting.
         * It is expected, that JS method will be called with the following parameters:
         *      cname - Common name for new certificate. Should be a convertible to String.
         *      serialNo - (optional) Serial number for the new certificate. Should be a convertible to Number. Defaults to 1.
         *      key - (optional) PEM-encoded private key string (encrypted PKCS8 blob). Should be a convertible to String or Node.Buffer. If not passed, then private key, associated with issuer certificate is used.
         *      passphrase - (optional) Passphrase to encrypt private key with. Should be a convertible to String. Default to an empty string.
         * Return value by JS method is a new issued certificate - NJSX509Certificate class instance. Undefined is returned on error. Incomplete or invalid input data causes JS exception thrown.
         *
         * @param info JS function parameter list info.
         */
        static void IssueCertificate(const FunctionCallbackInfo<Value>& info);

        /**
         * JS object of NJSX509Certificate class exported method for exporting X509 certificate DER/PEM formats.
         * It is expected, that JS method will be called with the following parameters:
         *  fmt - (optional) certificate data representation format. Default format is 'pem'. Supported formats are:
         *      'pem' - PEM representation;
         *      'der' - DER representation;
         *      'der_base64' - Base-64 encoded DER representation.
         * Return value by JS method is a string (for 'pem' and 'base64_der' formats) or Node.Buffer instance (for 'der'). Undefined is returned on error. Incomplete or invalid input data causes JS exception thrown.
         *
         * @param info JS function parameter list info.
         */
        static void ExportCertificate(const FunctionCallbackInfo<Value>& info);

    protected:  // NodeJS add-on exported methods.
        
        /**
         * Ad-on exported method for parsing X509 certificate collection into an array of JS objects of NJSX509Certificate class.
         * It is expected, that JS method will ve called with the following arguments:
         *  data - Certificate store data in one of supported formats, represented as a String or Node Buffer objet;
         *  fmt - (optional) certificate data representation format. Default format is 'pem'. Supported formats are:
         *      'pem' - PEM representation - concatenation of PEM represented certificates; data parameter may be String or Node.Buffer.
         *      'der' - DER representation - concatenation of DER represented certificates; data parameter should be Node.Buffer.
         *      'der_base64' - Base-64 encoded DER representation; data parameter may be String or Node.Buffer.
         *  Return value by JS method is an array of NJSX509Certificate objects. Parsing error causes a JS exception thrown and undefined value returned.
         *
         * @param args JS function parameter list info.
         */
        static void ParseCertificateStore(const FunctionCallbackInfo<Value>& args);
        
        /**
         * Ad-on exported method for parsing PKCS12 client certificate.
         * It is expected, that JS method will be called with the following arguments:
         *   data - Certificate store data in one of supported formats, represented as a String or Node Buffer objet;
         *   passphrase - Passphrase for PKCS12 bag decryption. Defaults to an empty string;
         *   fmt - (optional) certificate data representation format. Default format is 'pem'. Supported formats are:
         *     'pem' - PEM representation - concatenation of PEM represented certificates; data parameter may be String or Node.Buffer.
         *     'der' - DER representation - concatenation of DER represented certificates; data parameter should be Node.Buffer.
         *     'der_base64' - Base-64 encoded DER representation; data parameter may be String or Node.Buffer.
         *  Return value by JS method is a JS object with the following properties:
         *      'certificate' - Primary (client) certificate object. If there was a private key in input data bad, then it is associated with primary certificate.
         *      'pk' - Private key in PEM format, encrypted with the same passphrase, that was used to decrypt PKCS12 bag.
         *      'ca' - An array of NJSX509Certificate objects, representing ancestor certificates.
         *  Parsing error causes a JS exception thrown and undefined value returned.
         *
         * @param args JS function parameter list info.
         */
        static void ParsePKCS12(const FunctionCallbackInfo<Value>& args);
        
    public:
        
        /**
         * Helper class for representing an external v8::String resource with OpenSSL BIO memory buffer.
         */
        class MemBIOBufferStringResource final : public String::ExternalOneByteStringResource
        {
        public:

            /**
             * Designated constructor for class instances. Consumes given BIO memory buffer.
             *
             * @param bioBuf OpenSSL BIO memory buffer with string resource content.
             */
            MemBIOBufferStringResource(BUF_MEM* bioBuf) : bioBuf_(bioBuf)
            {
            }
            
            /**
             * Destructor for external string reqource. Releases BIO memory buffer.
             */
            virtual ~MemBIOBufferStringResource()
            {
                if( bioBuf_ != nullptr )
                {
                    BUF_MEM_free(bioBuf_);
                }
            }
            
            /**
             * String data getter from the underlying buffer.
             */
            const char* data() const
            {
                return bioBuf_ == nullptr ? nullptr : bioBuf_->data;
            }
            
            /**
             * Getter for the length of Latin-1 character string.
             */
            size_t length() const
            {
                return bioBuf_ == nullptr ? 0 : bioBuf_->length;
            }
            
        private:
            /// Forbidden default constructor.
            MemBIOBufferStringResource() = delete;
            
            /// Forbidden copy constructor.
            MemBIOBufferStringResource(const MemBIOBufferStringResource&) = delete;

            /// Forbidden move constructor.
            MemBIOBufferStringResource(MemBIOBufferStringResource&&) = delete;

            /// Forbidden assignment operator.
            MemBIOBufferStringResource& operator = (const MemBIOBufferStringResource&) = delete;

        private:
            /// Underlying OpenSSL BIO memory buffer.
            BUF_MEM* bioBuf_;
        };
        
    private:
        
        /// Persistent instance of constructor function for NJSX509Certificate JS class.
        static Persistent<Function> constructor_;
        
        /// Underlying native certificate instance.
        X509* x509Certificate_;
        
        /// Private key the certificate is signed with.
        EVP_PKEY* privateKey_;
        
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
