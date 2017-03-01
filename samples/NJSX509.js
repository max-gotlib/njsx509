const fs = require('fs');
var njsX509;
try {
    njsX509 = require('../build/Debug/NJSX509')
} catch(e) {
    njsX509 = require('../build/Release/NJSX509')
}

var cert
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
    console.log(`PK:      ${cert.publicKey}`);
    
//    var store = njsX509.importCertificateStore(certData, 'base64_der');
//    for(c of store) {
//        console.log(c.subjectName);
//        console.log(c.commonName);
//    }
} catch(e) {
    console.error(e);
}

console.log('-------');

if( cert === undefined || cert === null ) {
    console.log(`cert is '${cert}'`);
}