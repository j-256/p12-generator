const assert = require('node:assert/strict');
const test = require('node:test');
const forge = require('node-forge');

const {
    createFileMap,
    createPkcs12Asn1,
    getCertificateBundleFilenames,
    getCertificateValidity,
    getPasswordFileValue,
    isCertificateAuthority,
    normalizeArchiveEntries,
    parseValidityYears,
    rsaPrivateKeyMatchesCertificate
} = require('../main.js');

const CERTIFICATE_NOT_BEFORE = new Date('2025-01-01T00:00:00Z');
const CERTIFICATE_NOT_AFTER = new Date('2030-01-01T00:00:00Z');
const FRIENDLY_NAME = 'cert.staging.realm.customer.demandware.net';
const KEY_SIZE_BITS = 1024;
const PASSWORD = 'test-export-password';
const PROTOTYPE_COLLISION_FILENAME = '__proto__';
const PKCS12_OPTIONS = Object.freeze({
    algorithm: 'aes256',
    count: 2048,
    friendlyName: FRIENDLY_NAME,
    generateLocalKeyId: true,
    macAlgorithm: 'sha256',
    saltSize: 8,
    useMac: true
});

function createCertificate({
    issuerCertificate,
    issuerKey,
    keys,
    serialNumber,
    subjectName,
    extensions = []
}) {
    const certificate = forge.pki.createCertificate();
    const subject = [{ name: 'commonName', value: subjectName }];

    certificate.publicKey = keys.publicKey;
    certificate.serialNumber = serialNumber;
    certificate.validity.notBefore = CERTIFICATE_NOT_BEFORE;
    certificate.validity.notAfter = CERTIFICATE_NOT_AFTER;
    certificate.setSubject(subject);
    certificate.setIssuer(issuerCertificate ? issuerCertificate.subject.attributes : subject);
    certificate.setExtensions(extensions);
    certificate.sign(issuerKey || keys.privateKey, forge.md.sha256.create());

    return certificate;
}

test('stores uploaded files without prototype-backed filename collisions', () => {
    const prototypeNamedFile = { name: PROTOTYPE_COLLISION_FILENAME };
    const regularFile = { name: 'certificate.crt' };
    const fileMap = createFileMap([prototypeNamedFile, regularFile]);

    assert.equal(fileMap.size, 2);
    assert.equal(fileMap.get(PROTOTYPE_COLLISION_FILENAME), prototypeNamedFile);
    assert.equal(fileMap.get(regularFile.name), regularFile);
});

test('flattens a containing directory in an uploaded certificate archive', () => {
    const certificate = new Uint8Array([1]);
    const key = new Uint8Array([2]);
    const entries = normalizeArchiveEntries({
        'certificate-bundle/': new Uint8Array(),
        'certificate-bundle/host_01.crt': certificate,
        'certificate-bundle\\host_01.key': key
    });

    assert.deepEqual(
        entries.map(({ name }) => name),
        ['host_01.crt', 'host_01.key']
    );
    assert.equal(entries[0].data, certificate);
    assert.equal(entries[1].data, key);
});

test('rejects ambiguous duplicate basenames in an uploaded archive', () => {
    assert.throws(
        () => normalizeArchiveEntries({
            'first/host_01.crt': new Uint8Array([1]),
            'second/host_01.crt': new Uint8Array([2])
        }),
        /multiple files named "host_01\.crt"/
    );
});

test('creates a password-protected PKCS#12 archive with its certificate chain', () => {
    const caKeys = forge.pki.rsa.generateKeyPair(KEY_SIZE_BITS);
    const caCertificate = createCertificate({
        keys: caKeys,
        serialNumber: '01',
        subjectName: 'Test CA',
        extensions: [{ name: 'basicConstraints', cA: true }]
    });
    const userKeys = forge.pki.rsa.generateKeyPair(KEY_SIZE_BITS);
    const userCertificate = createCertificate({
        issuerCertificate: caCertificate,
        issuerKey: caKeys.privateKey,
        keys: userKeys,
        serialNumber: '02',
        subjectName: FRIENDLY_NAME,
        extensions: [{ name: 'basicConstraints', cA: false }]
    });

    const p12Asn1 = createPkcs12Asn1(
        forge,
        userKeys.privateKey,
        [userCertificate, caCertificate],
        PASSWORD,
        { ...PKCS12_OPTIONS }
    );
    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    const macAlgorithmOid = forge.asn1.derToOid(
        p12Asn1.value[2].value[0].value[0].value[0].value
    );
    const parsed = forge.pkcs12.pkcs12FromAsn1(
        forge.asn1.fromDer(p12Der),
        false,
        PASSWORD
    );
    const keyBags = parsed.getBags({
        bagType: forge.pki.oids.pkcs8ShroudedKeyBag
    })[forge.pki.oids.pkcs8ShroudedKeyBag];
    const certificateBags = parsed.getBags({
        bagType: forge.pki.oids.certBag
    })[forge.pki.oids.certBag];

    assert.equal(macAlgorithmOid, forge.pki.oids.sha256);
    assert.equal(keyBags.length, 1);
    assert.equal(certificateBags.length, 2);
    assert.equal(keyBags[0].key.n.compareTo(userKeys.privateKey.n), 0);
    assert.deepEqual(
        certificateBags.map(({ cert }) => cert.subject.getField('CN').value),
        [FRIENDLY_NAME, 'Test CA']
    );
    assert.deepEqual(keyBags[0].attributes.friendlyName, [FRIENDLY_NAME]);
    assert.deepEqual(
        certificateBags[0].attributes.localKeyId,
        keyBags[0].attributes.localKeyId
    );
    assert.equal(keyBags[0].attributes.localKeyId[0].length, 32);
    assert.throws(() => {
        forge.pkcs12.pkcs12FromAsn1(
            forge.asn1.fromDer(p12Der),
            false,
            'wrong-password'
        );
    });
});

test('creates certificate-bearing archives with documented 3DES encryption', () => {
    const keys = forge.pki.rsa.generateKeyPair(KEY_SIZE_BITS);
    const certificate = createCertificate({
        keys,
        serialNumber: '03',
        subjectName: '3DES Compatibility',
        extensions: [{ name: 'basicConstraints', cA: false }]
    });
    const p12Asn1 = createPkcs12Asn1(
        forge,
        keys.privateKey,
        certificate,
        PASSWORD,
        {
            ...PKCS12_OPTIONS,
            algorithm: '3des'
        }
    );
    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    const parsed = forge.pkcs12.pkcs12FromAsn1(
        forge.asn1.fromDer(p12Der),
        false,
        PASSWORD
    );
    const certificateBags = parsed.getBags({
        bagType: forge.pki.oids.certBag
    })[forge.pki.oids.certBag];

    assert.equal(certificateBags.length, 1);
    assert.equal(
        certificateBags[0].cert.subject.getField('CN').value,
        '3DES Compatibility'
    );
});

test('rejects unsupported MAC algorithms instead of downgrading to SHA-1', () => {
    const keys = forge.pki.rsa.generateKeyPair(KEY_SIZE_BITS);

    assert.throws(
        () => createPkcs12Asn1(
            forge,
            keys.privateKey,
            null,
            PASSWORD,
            {
                ...PKCS12_OPTIONS,
                macAlgorithm: 'sha999'
            }
        ),
        /Unsupported MAC algorithm: sha999/
    );
});

test('applies defaults without mutating caller-owned options', () => {
    const keys = forge.pki.rsa.generateKeyPair(KEY_SIZE_BITS);
    const certificate = createCertificate({
        keys,
        serialNumber: '03',
        subjectName: 'Frozen Options',
        extensions: [{ name: 'basicConstraints', cA: false }]
    });
    const options = Object.freeze({});
    const p12Asn1 = createPkcs12Asn1(
        forge,
        keys.privateKey,
        certificate,
        PASSWORD,
        options
    );
    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();

    assert.doesNotThrow(() => {
        forge.pkcs12.pkcs12FromAsn1(
            forge.asn1.fromDer(p12Der),
            false,
            PASSWORD
        );
    });
    assert.deepEqual(options, {});
});

test('rejects malformed iteration and salt options', () => {
    const keys = forge.pki.rsa.generateKeyPair(KEY_SIZE_BITS);
    const baseOptions = {
        ...PKCS12_OPTIONS,
        generateLocalKeyId: false
    };

    for (const [option, value] of [
        ['count', 0],
        ['count', -1],
        ['count', 1.5],
        ['saltSize', 0],
        ['saltSize', -1],
        ['saltSize', 1.5]
    ]) {
        assert.throws(
            () => createPkcs12Asn1(
                forge,
                keys.privateKey,
                null,
                PASSWORD,
                {
                    ...baseOptions,
                    [option]: value
                }
            ),
            new RegExp(`${option} must be a positive integer`)
        );
    }
});

test('matches a CA certificate to its RSA private key', () => {
    const caKeys = forge.pki.rsa.generateKeyPair(KEY_SIZE_BITS);
    const caCertificate = createCertificate({
        keys: caKeys,
        serialNumber: '04',
        subjectName: 'Key Pair Test CA',
        extensions: [{ name: 'basicConstraints', cA: true }]
    });
    const unrelatedKeys = forge.pki.rsa.generateKeyPair(KEY_SIZE_BITS);

    assert.equal(
        rsaPrivateKeyMatchesCertificate(caKeys.privateKey, caCertificate),
        true
    );
    assert.equal(
        rsaPrivateKeyMatchesCertificate(unrelatedKeys.privateKey, caCertificate),
        false
    );
});

test('accepts only certificates permitted to issue certificates', () => {
    const keys = forge.pki.rsa.generateKeyPair(KEY_SIZE_BITS);
    const validCa = createCertificate({
        keys,
        serialNumber: '05',
        subjectName: 'Valid CA',
        extensions: [{ name: 'basicConstraints', cA: true }]
    });
    const leaf = createCertificate({
        keys,
        serialNumber: '06',
        subjectName: 'Leaf',
        extensions: [{ name: 'basicConstraints', cA: false }]
    });
    const missingConstraints = createCertificate({
        keys,
        serialNumber: '07',
        subjectName: 'Missing Constraints'
    });
    const restrictedCa = createCertificate({
        keys,
        serialNumber: '08',
        subjectName: 'Restricted CA',
        extensions: [
            { name: 'basicConstraints', cA: true },
            { name: 'keyUsage', digitalSignature: true }
        ]
    });

    assert.equal(isCertificateAuthority(validCa), true);
    assert.equal(isCertificateAuthority(leaf), false);
    assert.equal(isCertificateAuthority(missingConstraints), false);
    assert.equal(isCertificateAuthority(restrictedCa), false);
});

test('preserves password whitespace while ignoring later file lines', () => {
    const password = ' password with spaces ';
    const keys = forge.pki.rsa.generateKeyPair(KEY_SIZE_BITS);
    const encryptedKey = forge.pki.encryptRsaPrivateKey(keys.privateKey, password);
    const passwordFile = `${password}\r\nignored line`;
    const extractedPassword = getPasswordFileValue(passwordFile);

    assert.equal(extractedPassword, password);
    assert.ok(forge.pki.decryptRsaPrivateKey(encryptedKey, extractedPassword));
});

test('accepts only positive whole-year validity values', () => {
    assert.equal(parseValidityYears('1'), 1);
    assert.equal(parseValidityYears(' 10 '), 10);
    assert.equal(parseValidityYears('0'), null);
    assert.equal(parseValidityYears('-1'), null);
    assert.equal(parseValidityYears('1.5'), null);
    assert.equal(parseValidityYears('1year'), null);
    assert.equal(parseValidityYears(String(Number.MAX_SAFE_INTEGER + 1)), null);
});

test('keeps generated certificate validity within the CA validity period', () => {
    const caCertificate = {
        validity: {
            notBefore: new Date('2025-01-01T00:00:00Z'),
            notAfter: new Date('2030-01-01T00:00:00Z')
        }
    };
    const now = new Date('2026-01-01T00:00:00Z');
    const validity = getCertificateValidity(caCertificate, 1, now);

    assert.deepEqual(validity, {
        notBefore: now,
        notAfter: new Date('2027-01-01T00:00:00Z')
    });
    assert.throws(
        () => getCertificateValidity(caCertificate, 1, new Date('2024-01-01T00:00:00Z')),
        /not valid yet/
    );
    assert.throws(
        () => getCertificateValidity(caCertificate, 1, new Date('2031-01-01T00:00:00Z')),
        /expired/
    );
    assert.throws(
        () => getCertificateValidity(caCertificate, 5, now),
        /exceeds CA expiration on 2030-01-01/
    );
});

test('selects the highest complete CA bundle suffix', () => {
    const hostname = 'cert.staging.realm.customer.demandware.net';
    const filenames = [
        `${hostname}_01.crt`,
        `${hostname}_01.key`,
        `${hostname}_01.txt`,
        `${hostname}_02.crt`,
        `${hostname}_02.key`,
        `${hostname}_02.txt`,
        `${hostname}_03.crt`,
        `${hostname}_03.key`,
        `${hostname}.srl`
    ];
    const bundle = getCertificateBundleFilenames(hostname, filenames);

    assert.equal(bundle.suffix, '02');
    assert.deepEqual(bundle.required, [
        `${hostname}_02.crt`,
        `${hostname}_02.key`,
        `${hostname}_02.txt`,
        `${hostname}.srl`
    ]);
});

test('uses the highest partial CA suffix for missing-file feedback', () => {
    const hostname = 'cert.staging.realm.customer.demandware.net';
    const bundle = getCertificateBundleFilenames(hostname, [
        `${hostname}_02.crt`,
        `${hostname}_10.key`,
        'other-host_99.crt'
    ]);

    assert.equal(bundle.suffix, '10');
    assert.deepEqual(bundle.required, [
        `${hostname}_10.crt`,
        `${hostname}_10.key`,
        `${hostname}_10.txt`,
        `${hostname}.srl`
    ]);
});
