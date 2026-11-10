const crypto = require('crypto');

function createSessionKey() {
    // Quantum vulnerable ECDH
    const alice = crypto.createECDH('secp256k1');
    alice.generateKeys();

    // Quantum vulnerable RSA keygen
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
    });

    // Weak MD5
    const hash = crypto.createHash('md5').update('session-data').digest('hex');

    return { alice, publicKey, hash };
}

module.exports = { createSessionKey };
