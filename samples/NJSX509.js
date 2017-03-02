const fs = require('fs');
var njsX509;
try {
    njsX509 = require('../build/Debug/NJSX509')
} catch(e) {
    njsX509 = require('../build/Release/NJSX509')
}

var cert

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
