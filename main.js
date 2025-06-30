// main.js

// This file is intentionally unminified for transparency.
// Forge is used for cryptographic operations, and fflate for zip handling.
// The only Forge API not used as-is is the PKCS#12 export (forge.pkcs12.toPkcs12Asn1), 
// which has been modified to allow specifying the MAC algorithm (sha1, sha256, sha384, sha512)
// and to encrypt the certificate chain, not just the private key (toPkcs12Asn1New).

// UI for expected/missing/unexpected files
(function() {
    const output = document.getElementById('output');
    const fileList = document.getElementById('fileList');
    const hostnameInput = document.getElementById('hostname');
    const filesInput = document.getElementById('files');
    function normalizeHostname(hostname) {
        return hostname.replace(/[_-]/g, '.')
            .replace(/^(production\.|development\.|staging\.|cert\.staging\.)/, '')
            .replace(/\.demandware\.net$/, '')
            .replace(/^/, 'cert.staging.')
            .replace(/$/, '.demandware.net');
    }
    function getExpectedFilenames(hostname) {
        const normHost = normalizeHostname(hostname);
        return [
            `${normHost}_01.crt`,
            `${normHost}_01.key`,
            `${normHost}_01.txt`,
            `${normHost}.srl`
        ];
    }
    const iconMarkup = {
        check: `<img src="static/icons/check-mark.svg" alt="✔" class="inline-icon" width="20" height="20" loading="lazy">`,
        x:     `<img src="static/icons/red-x.svg" alt="✖" class="inline-icon" width="20" height="20" loading="lazy">`
    }
    function renderFileStatus() {
        const hostname = hostnameInput.value.trim() || hostnameInput.placeholder;
        const expectedFiles = getExpectedFilenames(hostname);
        const uploaded = filesInput.files ? Array.from(filesInput.files) : [];
        // Check for a zip file
        const zipFile = uploaded.find(f => f.name.endsWith('.zip'));
        if (zipFile) {
            // Only unzip and log files if we haven't already for this file
            if (renderFileStatus.lastZipName !== zipFile.name || renderFileStatus.lastZipSize !== zipFile.size) {
                renderFileStatus.lastZipName = zipFile.name;
                renderFileStatus.lastZipSize = zipFile.size;
                const reader = new FileReader();
                reader.onload = function(e) {
                    const buffer = new Uint8Array(e.target.result);
                    fflate.unzip(buffer, (err, files) => {
                        if (err) {
                            output.style.display = null; // show output
                            output.innerHTML = `<span style='color:red'>Error reading zip: ${err.message || JSON.stringify(err)}</span>`;
                            renderFileStatus.zipNames = [];
                            return;
                        }
                        const zipNames = Object.keys(files);
                        renderFileStatus.zipNames = zipNames;
                        logToPage('Files in uploaded zip:\n  ' + zipNames.join('\n  '));
                        updateZipFileStatus();
                    });
                };
                reader.readAsArrayBuffer(zipFile);
                return;
            } else if (renderFileStatus.zipNames) {
                updateZipFileStatus();
                return;
            } else {
                return;
            }
            function updateZipFileStatus() {
                const zipNames = renderFileStatus.zipNames || [];
                let html = '<b>Required files:</b><ul class="required-files">';
                for (const fname of expectedFiles) {
                    const has = zipNames.includes(fname);
                    html += `<li>${has ? iconMarkup.check : iconMarkup.x} ${fname}</li>`;
                }
                html += '</ul>';
                // Unexpected files
                const unexpected = zipNames.filter(f => !expectedFiles.includes(f) && !f.endsWith('.zip'));
                if (unexpected.length) {
                    html += `<b class="unexpected-files">Unexpected files:</b><ul>`;
                    for (const fname of unexpected) {
                        html += `<li>${iconMarkup.x} ${fname}</li>`;
                    }
                    html += '</ul>';
                }
                fileList.innerHTML = html;
            }
        } else {
            // Clear zip cache if no zip is present
            renderFileStatus.lastZipName = undefined;
            renderFileStatus.lastZipSize = undefined;
            renderFileStatus.zipNames = undefined;
            // No zip, use uploaded files
            const uploadedNames = uploaded.map(f => f.name);
            let html = '<b>Required files:</b><ul>';
            for (const fname of expectedFiles) {
                const has = uploadedNames.includes(fname);
                html += `<li>${has ? iconMarkup.check : iconMarkup.x} ${fname}</li>`;
            }
            html += '</ul>';
            // Unexpected files
            const unexpected = uploadedNames.filter(f => !expectedFiles.includes(f) && !f.endsWith('.zip'));
            if (unexpected.length) {
                html += `<b>Unexpected files:</b><ul>`;
                for (const fname of unexpected) {
                    html += `<li>${iconMarkup.x} ${fname}</li>`;
                }
                html += '</ul>';
            }
            fileList.innerHTML = html;
        }
    }
    hostnameInput.addEventListener('input', renderFileStatus);
    filesInput.addEventListener('change', renderFileStatus);
    renderFileStatus();
})();

// main form submission logic
document.getElementById('certForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const output = document.getElementById('output');
    output.textContent = '';
    try {
        const hostname = document.getElementById('hostname').value.trim();
        const years = parseInt(document.getElementById('years').value, 10);
        const filesInput = document.getElementById('files');
        if (!hostname || !years || !filesInput.files.length) {
            output.style.display = null; // show output
            output.textContent = 'Please fill all fields and upload the required files.';
            return;
        }

        // No matter which hostname is entered, normalize to cert.staging.realm.customer.demandware.net
        function normalizeHostname(hostname) {
            return hostname.replace(/[_-]/g, '.')
                .replace(/^(production\.|development\.|staging\.|cert\.staging\.)/, '')
                .replace(/\.demandware\.net$/, '')
                .replace(/^/, 'cert.staging.')
                .replace(/$/, '.demandware.net');
        }

        const normHost = normalizeHostname(hostname);
        console.log(`Normalized Hostname: ${normHost}`);

        // Required filenames
        const caCertFilename = `${normHost}_01.crt`;
        const caKeyFilename = `${normHost}_01.key`;
        const caPassFilename = `${normHost}_01.txt`;
        const caSerialFilename = `${normHost}.srl`;
        const requiredFiles = [caCertFilename, caKeyFilename, caPassFilename, caSerialFilename];

        // Build fileMap from individual files
        let fileMap = {};
        for (let file of filesInput.files) {
            fileMap[file.name] = file;
        }

        // If a zip is present, extract its files and add to fileMap
        const zipFile = Array.from(filesInput.files).find(f => f.name.endsWith('.zip'));
        if (zipFile) {
            output.style.display = null; // show output
            output.textContent = 'Extracting zip...';
            let buffer;
            try {
                buffer = await zipFile.arrayBuffer();
            } catch (err) {
                output.innerHTML = `<span style='color:red'>Error reading zip file: ${err.message || JSON.stringify(err)}</span>`;
                throw err;
            }
            await new Promise((resolve, reject) => {
                fflate.unzip(new Uint8Array(buffer), (err, files) => {
                    if (err) {
                        output.innerHTML = `<span style='color:red'>Error extracting zip: ${err.message || JSON.stringify(err)}</span>`;
                        reject(err);
                        return;
                    }
                    for (let [name, data] of Object.entries(files)) {
                        fileMap[name] = new File([data], name);
                    }
                    output.textContent = 'Zip extracted successfully.';
                    resolve();
                });
            });
        }

        // Check for required files
        const missing = requiredFiles.filter(f => !(f in fileMap));
        if (missing.length) {
            output.style.display = null; // show output
            output.innerHTML = `<span style='color:red'>Missing required file(s):<br>${missing.join('<br>')}</span>`;
            console.log(`Missing Files: ${missing.join(', ')}`);
            return;
        }

        output.style.display = null; // show output
        output.textContent = 'Working...';
        console.log('All required files found. Starting PKI logic...');

        // --- PKI logic start ---
        try {
            function pemToPrivateKey(pem, password) {
                if (/Proc-Type: 4,ENCRYPTED/.test(pem)) {
                    return forge.pki.decryptRsaPrivateKey(pem, password);
                } else {
                    return forge.pki.privateKeyFromPem(pem);
                }
            }

            // 1. Read CA cert, key, password, serial
            // Note: We do NOT use the CA serial from the .srl file,
            // instead we generate a new one based on the current unix timestamp.
            // Usually the number in the .srl file is used and then incremented,
            // but we cannot increment it in the browser so we cannot use it at all.
            const readAsText = file => file.text();
            const [caCertPem, caKeyPem, caPassText, caSerialText] = await Promise.all([
                readAsText(fileMap[caCertFilename]),
                readAsText(fileMap[caKeyFilename]),
                readAsText(fileMap[caPassFilename]),
                readAsText(fileMap[caSerialFilename])
            ]);

            // 2. Get export password
            const exportPassword = document.getElementById('exportPassword').value.trim();

            // 3. Generate user keypair and CSR
            logToPage('Generating keypair and CSR...');
            const userKeyPair = forge.pki.rsa.generateKeyPair(2048);

            // CSR subject info
            const userCN = normHost;
            const country = document.getElementById('country').value.trim();
            const state = document.getElementById('state').value.trim();
            const locality = document.getElementById('locality').value.trim();
            const organization = document.getElementById('organization').value.trim();
            const orgUnit = document.getElementById('orgUnit').value.trim();
            const email = document.getElementById('email').value.trim();

            const csr = forge.pki.createCertificationRequest();
            csr.publicKey = userKeyPair.publicKey;
            csr.setSubject([
                { name: 'countryName', value: country },
                { name: 'stateOrProvinceName', value: state },
                { name: 'localityName', value: locality },
                { name: 'organizationName', value: organization },
                { name: 'organizationalUnitName', value: orgUnit },
                { name: 'commonName', value: userCN },
                { name: 'emailAddress', value: email }
            ]);
            csr.sign(userKeyPair.privateKey, forge.md.sha256.create());
            console.log('Generated CSR:', csr);

            // 4. Parse CA cert and key
            logToPage('Parsing CA cert and key...');
            const caCertObj = forge.pki.certificateFromPem(caCertPem);
            const caKeyObj = pemToPrivateKey(caKeyPem, caPassText.trim());
            if (!caKeyObj) {
                logToPage('Failed to parse/import CA private key.');
                output.innerHTML = `<span style='color:red'>Failed to parse/import CA private key.</span>`;
                throw new Error('Failed to parse/import CA private key.');
            }
            console.log('Parsed CA Cert Object:', caCertObj);
            console.log('Parsed CA Key Object:', caKeyObj);

            // 5. Sign CSR to create user cert
            logToPage('Signing certificate...');
            const userCert = forge.pki.createCertificate();
            userCert.serialNumber = (Date.now()).toString();
            userCert.validity.notBefore = new Date();
            userCert.validity.notAfter = new Date(Date.now() + years * 365 * 24 * 60 * 60 * 1000);
            userCert.setSubject(csr.subject.attributes);
            userCert.setIssuer(caCertObj.subject.attributes);
            userCert.publicKey = userKeyPair.publicKey;
            userCert.setExtensions([
                { name: 'basicConstraints', cA: false }
            ]);
            userCert.sign(caKeyObj, forge.md.sha256.create());
            console.log('Signed User Certificate:', userCert);

            // 6. Export PKCS#12
            logToPage('Exporting PKCS#12 (.p12)...');
            // We use our own version of forge.pkcs12.toPkcs12Asn1 because Forge hardcodes sha1 for PKCS#12 MAC
            // https://github.com/digitalbazaar/forge/blob/2bb97afb5058285ef09bcf1d04d6bd6b87cffd58/lib/pkcs12.js#L796
            const p12Asn1 = toPkcs12Asn1New(
                userKeyPair.privateKey,
                [userCert, caCertObj],
                exportPassword,
                {
                    generateLocalKeyId: true,
                    friendlyName: userCN,
                    algorithm: 'aes256',
                    useMac: true,
                    macAlgorithm: 'sha256',
                    saltSize: 8,
                    count: 2048
                }
            );
            const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
            const blob = new Blob([new Uint8Array([...p12Der].map(c => c.charCodeAt(0)))], { type: 'application/x-pkcs12' });
            // Create a green download button with save.svg icon
            const button = document.getElementById('downloadButton');
            button.style.display = null; // unhide
            button.onclick = function() {
                // Append and click a link to trigger the download, then revoke the object URL to release memory
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = `${userCN}.p12`;
                document.body.appendChild(a);
                a.click();
                setTimeout(() => {
                    URL.revokeObjectURL(a.href);
                    document.body.removeChild(a);
                }, 100);
            };
            output.textContent = `PKCS#12 cert ready for download!`;
            logToPage('Done.');
            console.log('PKCS#12 Export Complete.');
        } catch (err) {
            logToPage('Error during certificate generation: ' + (err.message || JSON.stringify(err)));
            output.innerHTML = `<span style='color:red'>Error during certificate generation: ${err.message || JSON.stringify(err)}</span>`;
            console.error('Error during certificate generation:', err);
            throw err;
        }
    } catch (err) {
        output.innerHTML = `<span style='color:red'>Unexpected error: ${err.message || JSON.stringify(err)}</span>`;
        throw err;
    }
    /**
     * A version of forge.pkcs12.toPkcs12Asn1 that allows specifying the MAC algorithm.
     * Also encrypts the certificate chain, not just the private key.
     *
     * @param key the private key.
     * @param cert the certificate (may be an array of certificates in order
     *          to specify a certificate chain).
     * @param password the password to use, null for none.
     * @param options:
     *          algorithm the encryption algorithm to use
     *            ('aes128', 'aes192', 'aes256', '3des'), defaults to 'aes128'.
     *          macAlgorithm the MAC algorithm to use
     *            ('sha1', 'sha256', 'sha384', 'sha512'), defaults to 'sha1'.
     *          count the iteration count to use.
     *          saltSize the salt size to use.
     *          useMac true to include a MAC, false not to, defaults to true.
     *          localKeyId the local key ID to use, in hex.
     *          friendlyName the friendly name to use.
     *          generateLocalKeyId true to generate a random local key ID,
     *            false not to, defaults to true.
     *
     * @return the PKCS#12 PFX ASN.1 object.
     */
    function toPkcs12Asn1New(key, cert, password, options) {
        const asn1 = forge.asn1;
        const pki = forge.pki;
        const p12 = forge.pkcs12;
        // set default options
        options = options || {};
        options.saltSize = options.saltSize || 8;
        options.count = options.count || 2048;
        options.algorithm = options.algorithm || options.encAlgorithm || 'aes128';
        if (!('useMac' in options)) {
            options.useMac = true;
        }
        if (!('localKeyId' in options)) {
            options.localKeyId = null;
        }
        if (!('generateLocalKeyId' in options)) {
            options.generateLocalKeyId = true;
        }

        var localKeyId = options.localKeyId;
        var bagAttrs;
        if (localKeyId !== null) {
            localKeyId = forge.util.hexToBytes(localKeyId);
        } else if (options.generateLocalKeyId) {
            // use SHA-256 of paired cert, if available
            if (cert) {
                var pairedCert = forge.util.isArray(cert) ? cert[0] : cert;
                if (typeof pairedCert === 'string') {
                    pairedCert = pki.certificateFromPem(pairedCert);
                }
                var sha256 = forge.md.sha256.create();
                sha256.update(asn1.toDer(pki.certificateToAsn1(pairedCert)).getBytes());
                localKeyId = sha256.digest().getBytes();
            } else {
                // FIXME: consider using SHA-256 of public key (which can be generated
                // from private key components), see: cert.generateSubjectKeyIdentifier
                // generate random bytes
                localKeyId = forge.random.getBytes(20);
            }
        }

        var attrs = [];
        if (localKeyId !== null) {
            attrs.push(
                // localKeyID
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                    // attrId
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                        asn1.oidToDer(pki.oids.localKeyId).getBytes()),
                    // attrValues
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
                            localKeyId)
                    ])
                ]));
        }
        if ('friendlyName' in options) {
            attrs.push(
                // friendlyName
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                    // attrId
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                        asn1.oidToDer(pki.oids.friendlyName).getBytes()),
                    // attrValues
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BMPSTRING, false,
                            options.friendlyName)
                    ])
                ]));
        }

        if (attrs.length > 0) {
            bagAttrs = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, attrs);
        }

        // collect contents for AuthenticatedSafe
        var contents = [];

        // create safe bag(s) for certificate chain
        var chain = [];
        if (cert !== null) {
            if (forge.util.isArray(cert)) {
                chain = cert;
            } else {
                chain = [cert];
            }
        }

        var certSafeBags = [];
        for (var i = 0; i < chain.length; ++i) {
            // convert cert from PEM as necessary
            cert = chain[i];
            if (typeof cert === 'string') {
                cert = pki.certificateFromPem(cert);
            }

            // SafeBag
            var certBagAttrs = (i === 0) ? bagAttrs : undefined;
            var certAsn1 = pki.certificateToAsn1(cert);
            var certSafeBag =
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                    // bagId
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                        asn1.oidToDer(pki.oids.certBag).getBytes()),
                    // bagValue
                    asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                        // CertBag
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                            // certId
                            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                                asn1.oidToDer(pki.oids.x509Certificate).getBytes()),
                            // certValue (x509Certificate)
                            asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                                asn1.create(
                                    asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
                                    asn1.toDer(certAsn1).getBytes())
                            ])])]),
                    // bagAttributes (OPTIONAL)
                    certBagAttrs
                ]);
            certSafeBags.push(certSafeBag);
        }

        if (certSafeBags.length > 0) {
            // SafeContents
            var certSafeContents = asn1.create(
                asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, certSafeBags);

            // Used to encrypt the cert chain. By default, only the private key is encrypted.
            // It's unusual to encrypt more than the private key, but that is what the openssl
            // commands do.
            function encryptSafeContentsAsEncryptedData(safeContentsBytes, password, options) {
                options = options || {};
                const saltSize = options.saltSize || 8;
                const count = options.count || 2048;
                const prf = (options.macAlgorithm || 'sha256').toLowerCase();
                const algorithm = (options.algorithm || 'aes256').toLowerCase();

                const prfOid = {
                    sha1: forge.pki.oids.hmacWithSHA1,
                    sha256: forge.pki.oids.hmacWithSHA256,
                    sha384: forge.pki.oids.hmacWithSHA384,
                    sha512: forge.pki.oids.hmacWithSHA512
                }[prf];
                if (!prfOid) throw new Error(`Unsupported PRF algorithm: ${prf}`);

                const keySize = {
                    aes128: 16,
                    aes192: 24,
                    aes256: 32
                }[algorithm];
                if (!keySize) throw new Error(`Unsupported algorithm: ${algorithm}`);

                const cipherOid = {
                    aes128: forge.pki.oids['aes128-CBC'],
                    aes192: forge.pki.oids['aes192-CBC'],
                    aes256: forge.pki.oids['aes256-CBC']
                }[algorithm];

                const salt = forge.random.getBytes(saltSize);
                const iv = forge.random.getBytes(16);
                const key = forge.pkcs5.pbkdf2(password, salt, count, keySize, forge.md[prf].create());

                const cipher = forge.cipher.createCipher(`AES-CBC`, key);
                cipher.start({ iv });
                cipher.update(forge.util.createBuffer(safeContentsBytes));
                cipher.finish();
                const encryptedContent = cipher.output.getBytes();

                // Build PBKDF2-params ASN.1
                const pbkdf2Params = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, salt),
                    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false,
                        forge.util.hexToBytes(count.toString(16))),
                    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [ // prf
                        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
                            forge.asn1.oidToDer(prfOid).getBytes()),
                        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, '')
                    ])
                ]);

                // PBES2-params
                const pbes2Params = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                    // keyDerivationFunc
                    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
                            forge.asn1.oidToDer(forge.pki.oids['pkcs5PBKDF2']).getBytes()),
                        pbkdf2Params
                    ]),
                    // encryptionScheme
                    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
                            forge.asn1.oidToDer(cipherOid).getBytes()),
                        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, iv)
                    ])
                ]);

                // contentEncryptionAlgorithm = PBES2 + params
                const contentEncryptionAlgorithm = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
                        forge.asn1.oidToDer(forge.pki.oids['pkcs5PBES2']).getBytes()),
                    pbes2Params
                ]);

                // EncryptedContentInfo
                const encryptedContentInfo = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                    // contentType: data
                    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
                        forge.asn1.oidToDer(forge.pki.oids.data).getBytes()),
                    contentEncryptionAlgorithm,
                    // encryptedContent [0]
                    forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, false, encryptedContent)
                ]);

                // EncryptedData
                const encryptedData = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false,
                        forge.util.hexToBytes('00')), // version
                    encryptedContentInfo
                ]);

                // ContentInfo (EncryptedData wrapper)
                return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
                        forge.asn1.oidToDer(forge.pki.oids.encryptedData).getBytes()),
                    forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [encryptedData])
                ]);
            }

            const certSafeContentsBytes = forge.asn1.toDer(certSafeContents).getBytes();
            const certCI = encryptSafeContentsAsEncryptedData(certSafeContentsBytes, password, options);
            contents.push(certCI);
        }

        // create safe contents for private key
        var keyBag = null;
        if (key !== null) {
            // SafeBag
            var pkAsn1 = pki.wrapRsaPrivateKey(pki.privateKeyToAsn1(key));
            if (password === null) {
                // no encryption
                keyBag = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                    // bagId
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                        asn1.oidToDer(pki.oids.keyBag).getBytes()),
                    // bagValue
                    asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                        // PrivateKeyInfo
                        pkAsn1
                    ]),
                    // bagAttributes (OPTIONAL)
                    bagAttrs
                ]);
            } else {
                // encrypted PrivateKeyInfo
                keyBag = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                    // bagId
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                        asn1.oidToDer(pki.oids.pkcs8ShroudedKeyBag).getBytes()),
                    // bagValue
                    asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                        // EncryptedPrivateKeyInfo
                        pki.encryptPrivateKeyInfo(pkAsn1, password, options)
                    ]),
                    // bagAttributes (OPTIONAL)
                    bagAttrs
                ]);
            }

            // SafeContents
            var keySafeContents =
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [keyBag]);

            // ContentInfo
            var keyCI =
                // PKCS#7 ContentInfo
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                    // contentType
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                        // OID for the content type is 'data'
                        asn1.oidToDer(pki.oids.data).getBytes()),
                    // content
                    asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                        asn1.create(
                            asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
                            asn1.toDer(keySafeContents).getBytes())
                    ])
                ]);
            contents.push(keyCI);
        }

        // create AuthenticatedSafe by stringing together the contents
        var safe = asn1.create(
            asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, contents);

        var macData;
        if (options.useMac) {
            // MacData
            const digestAlgorithm = (options.macAlgorithm || 'sha1').toLowerCase();
            let md, oid, keyLen;

            switch (digestAlgorithm) {
                case 'sha256':
                    md = forge.md.sha256.create();
                    oid = pki.oids.sha256;
                    keyLen = 32;
                    break;
                case 'sha384':
                    md = forge.md.sha384.create();
                    oid = pki.oids.sha384;
                    keyLen = 48;
                    break;
                case 'sha512':
                    md = forge.md.sha512.create();
                    oid = pki.oids.sha512;
                    keyLen = 64;
                    break;
                case 'sha1':
                default:
                    md = forge.md.sha1.create();
                    oid = pki.oids.sha1;
                    keyLen = 20;
                    break;
            }

            const macSaltBytes = forge.random.getBytes(options.saltSize);
            const macSalt = new forge.util.ByteBuffer(macSaltBytes);
            const count = options.count;
            const key = p12.generateKey(password, macSalt, 3, count, keyLen, md);
            const mac = forge.hmac.create();
            mac.start(md, key);
            mac.update(asn1.toDer(safe).getBytes());
            const macValue = mac.getMac();
            macData = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                // mac DigestInfo
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                    // digestAlgorithm
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                        // algorithm
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                            asn1.oidToDer(oid).getBytes()),
                        // parameters = Null
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
                    ]),
                    // digest
                    asn1.create(
                        asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING,
                        false, macValue.getBytes())
                ]),
                // macSalt OCTET STRING
                asn1.create(
                    asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, macSaltBytes),
                // iterations INTEGER (XXX: Only support count < 65536)
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
                    asn1.integerToDer(count).getBytes()
                )
            ]);
        }

        // PFX
        return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            // version (3)
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
                asn1.integerToDer(3).getBytes()),
            // PKCS#7 ContentInfo
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                // contentType
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                    // OID for the content type is 'data'
                    asn1.oidToDer(pki.oids.data).getBytes()),
                // content
                asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                    asn1.create(
                        asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
                        asn1.toDer(safe).getBytes())
                ])
            ]),
            macData
        ]);
    };
});

function logToPage(msg) {
    const log = document.getElementById('console-log');
    log.textContent += (msg + '\n');
    log.scrollTop = log.scrollHeight;
}