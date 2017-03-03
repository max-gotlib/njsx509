const fs = require('fs');
var njsX509;
try {
    njsX509 = require('../build/Debug/NJSX509')
} catch(e) {
    njsX509 = require('../build/Release/NJSX509')
}

var cert

try {
    console.log('============================================================');
    let identData = fs.readFileSync('client.identity');
    let rv = njsX509.importPKCS12(identData, 'ipad', 'der');
    cert = rv.certificate;
    console.log(cert);
    console.log('=======================');
    var encData = cert.encryptPublic('01234567890');
    console.log(encData.toString('base64'))
    console.log('=======================');
    var decData = cert.decryptPrivate(encData);
    console.log(decData.toString('utf8'))
    console.log('============================================================');
    encData = null;
    decData = null;
    cert = null;
} catch(e) {
    console.error(e);
}

while(2*2 == 4) {
    console.log(1);
}

try {
//    let identData = fs.readFileSync('client.identity');
//    let rv = njsX509.importPKCS12(identData, 'ipad', 'der');
//    let caCert = rv.certificate;
//    let caPK = rv.pk
    
    let caCert = new njsX509.NJSX509Certificate();

    cert = caCert.issueCertificate('0123456789-10-123456789-20-123456789-30-123456789-40', 532); //, caPK, 'ipad');
    console.log(cert);
    console.log('============================================================');
    console.log(cert.getPrivateKey('ipad'));
} catch(e) {
    console.error(e);
}

try {
    cert = new njsX509.NJSX509Certificate();
    let pkData = fs.readFileSync('key.pem');
    cert.setPrivateKey(pkData, 'ipad');
    console.log(cert);
    console.log(cert.getPrivateKey('123'));
} catch(e) {
    console.error(e);
}

try {
//    cert = njsX509.X509CertificateFromDER(10);
//    cert = new njsX509.NJSX509Certificate(3);
//    cert = njsX509.NJSX509Certificate(12);
//    cert = njsX509.NJSX509Certificate(Buffer.from('sample cert data', 'utf8'))
    
//    let certData = fs.readFileSync('zzz.cer');
//    cert = njsX509.NJSX509Certificate(certData, 'DER');
//    let certData = fs.readFileSync('c.pem');
//    cert = new njsX509.NJSX509Certificate(certData, 'pem');
//    console.log(cert.subjectName);
//    console.log(cert.commonName);
    
    let certData = fs.readFileSync('zzz.b64');
    cert = new njsX509.NJSX509Certificate(certData, 'base64_der');
    console.log(`Subject: ${cert.subjectName}`);
    console.log(`Issuer:  ${cert.issuer}`);
    console.log(`CN:      ${cert.commonName}`);
    console.log(`Valid:   ${cert.validSince.toString()} --- ${cert.notValidAfter.toString()}`);
    console.log(`PubKey:  ${cert.publicKey}`);
    console.log(`PrvKey:  ${cert.getPrivateKey('123')}`);
    
//    var store = njsX509.importCertificateStore(certData, 'base64_der');
//    for(c of store) {
//        console.log(c.subjectName);
//        console.log(c.commonName);
//    }
} catch(e) {
    console.error(e);
}

try {
    var certData = fs.readFileSync('client.identity');
    let rv = njsX509.importPKCS12(certData, "ipad", "der");
    console.log(rv);
    
    certData = fs.readFileSync('client.b64');
    rv = njsX509.importPKCS12(certData, "ipad", "pem");
    console.log(rv);
} catch(e) {
    console.error(e);
}

console.log('-------');

if( cert === undefined || cert === null ) {
    console.log(`cert is '${cert}'`);
}
