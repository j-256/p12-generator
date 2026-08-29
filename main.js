// main.js

// This file is intentionally unminified for transparency
// Forge is used for cryptographic operations, and fflate for zip handling
// The only Forge API not used as-is is the PKCS#12 export (forge.pkcs12.toPkcs12Asn1),
// which has been modified to allow specifying the MAC algorithm (sha1, sha256, sha384, sha512)
// and to encrypt the certificate chain, not just the private key (createPkcs12Asn1)

const FILE_SECTION_LABELS = Object.freeze({
    required: 'Required files:',
    unexpected: 'Unexpected files:'
});
const CA_BUNDLE_EXTENSIONS = Object.freeze(['crt', 'key', 'txt']);
const CA_BUNDLE_FILE_PATTERN = /^(\d{2})\.(crt|key|txt)$/;
const ARCHIVE_DIRECTORY_PATTERN = /[\\/]$/;
const ARCHIVE_PATH_SEPARATOR_PATTERN = /[\\/]/;
const CA_CERTIFICATE_CANNOT_ISSUE_MESSAGE =
    'CA certificate is not permitted to issue certificates.';
const CA_KEY_MISMATCH_MESSAGE = 'CA certificate does not match its private key.';
const DAYS_PER_YEAR = 365;
const DEFAULT_CA_BUNDLE_SUFFIX = '01';
const DEFAULT_PKCS12_ITERATION_COUNT = 2048;
const DEFAULT_PKCS12_SALT_SIZE = 8;
const ERROR_CONTEXTS = Object.freeze({
    certificateGeneration: 'Error during certificate generation',
    fileProcessing: 'Error processing certificate files'
});
const MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000;
const PASSWORD_LINE_ENDING_PATTERN = /\r\n|\n|\r/;
const POSITIVE_INTEGER_PATTERN = /^[1-9]\d*$/;
const STATUS_ICONS = Object.freeze({
    present: Object.freeze({
        alt: '✔',
        src: 'static/icons/check-mark.svg'
    }),
    missing: Object.freeze({
        alt: '✖',
        src: 'static/icons/red-x.svg'
    })
});
const STATUS_ICON_SIZE = 20;

function appendFileSection(container, label, filenames, isPresent, options = {}) {
    const heading = document.createElement('b');
    const list = document.createElement('ul');

    heading.textContent = label;
    if (options.headingClass) {
        heading.className = options.headingClass;
    }
    if (options.listClass) {
        list.className = options.listClass;
    }

    for (const filename of filenames) {
        const iconSettings = isPresent(filename) ? STATUS_ICONS.present : STATUS_ICONS.missing;
        const icon = document.createElement('img');
        const item = document.createElement('li');

        icon.src = iconSettings.src;
        icon.alt = iconSettings.alt;
        icon.className = 'inline-icon';
        icon.width = STATUS_ICON_SIZE;
        icon.height = STATUS_ICON_SIZE;
        icon.loading = 'lazy';
        item.append(icon, document.createTextNode(filename));
        list.append(item);
    }

    container.append(heading, list);
}

function renderFileLists(container, expectedFiles, uploadedFiles) {
    const unexpectedFiles = uploadedFiles.filter(
        filename => !expectedFiles.includes(filename) && !filename.endsWith('.zip')
    );

    container.replaceChildren();
    appendFileSection(
        container,
        FILE_SECTION_LABELS.required,
        expectedFiles,
        filename => uploadedFiles.includes(filename),
        { listClass: 'required-files' }
    );
    if (unexpectedFiles.length > 0) {
        appendFileSection(
            container,
            FILE_SECTION_LABELS.unexpected,
            unexpectedFiles,
            () => false,
            { headingClass: 'unexpected-files' }
        );
    }
}

function getErrorMessage(error) {
    if (error && typeof error.message === 'string') {
        return error.message;
    }

    try {
        return JSON.stringify(error) ?? String(error);
    } catch {
        return String(error);
    }
}

function getPasswordFileValue(contents) {
    return contents.split(PASSWORD_LINE_ENDING_PATTERN, 1)[0];
}

function createFileMap(files = []) {
    const fileMap = new Map();

    for (const file of files) {
        fileMap.set(file.name, file);
    }

    return fileMap;
}

function normalizeArchiveEntries(files = {}) {
    const entries = [];
    const filenames = new Set();

    for (const [archivePath, data] of Object.entries(files)) {
        if (ARCHIVE_DIRECTORY_PATTERN.test(archivePath)) {
            continue;
        }

        const name = archivePath.split(ARCHIVE_PATH_SEPARATOR_PATTERN).pop();

        if (filenames.has(name)) {
            throw new Error(`Archive contains multiple files named "${name}".`);
        }
        filenames.add(name);
        entries.push({ data, name });
    }

    return entries;
}

function parseValidityYears(value) {
    const normalizedValue = String(value).trim();

    if (!POSITIVE_INTEGER_PATTERN.test(normalizedValue)) {
        return null;
    }

    const years = Number(normalizedValue);

    return Number.isSafeInteger(years) ? years : null;
}

function validatePositiveIntegerOption(name, value) {
    if (!Number.isSafeInteger(value) || value < 1) {
        throw new Error(`${name} must be a positive integer.`);
    }
}

function getCertificateValidity(caCertificate, years, now = new Date()) {
    const caNotBefore = caCertificate && caCertificate.validity &&
        caCertificate.validity.notBefore;
    const caNotAfter = caCertificate && caCertificate.validity &&
        caCertificate.validity.notAfter;
    const notBefore = new Date(now);

    if (
        !(caNotBefore instanceof Date) ||
        !(caNotAfter instanceof Date) ||
        !Number.isFinite(caNotBefore.getTime()) ||
        !Number.isFinite(caNotAfter.getTime()) ||
        caNotBefore > caNotAfter
    ) {
        throw new Error('CA certificate has an invalid validity period.');
    }
    if (!Number.isFinite(notBefore.getTime())) {
        throw new Error('Certificate start time is invalid.');
    }
    if (notBefore < caNotBefore) {
        throw new Error('CA certificate is not valid yet.');
    }
    if (notBefore > caNotAfter) {
        throw new Error('CA certificate has expired.');
    }

    const notAfter = new Date(
        notBefore.getTime() + years * DAYS_PER_YEAR * MILLISECONDS_PER_DAY
    );

    if (!Number.isFinite(notAfter.getTime()) || notAfter > caNotAfter) {
        const caExpirationDate = caNotAfter.toISOString().slice(0, 10);

        throw new Error(
            `Requested certificate lifetime exceeds CA expiration on ${caExpirationDate}.`
        );
    }

    return { notAfter, notBefore };
}

function isCertificateAuthority(certificate) {
    if (!certificate || typeof certificate.getExtension !== 'function') {
        return false;
    }

    const basicConstraints = certificate.getExtension('basicConstraints');
    const keyUsage = certificate.getExtension('keyUsage');

    return Boolean(
        basicConstraints &&
        basicConstraints.cA === true &&
        (!keyUsage || keyUsage.keyCertSign === true)
    );
}

function rsaPrivateKeyMatchesCertificate(privateKey, certificate) {
    const publicKey = certificate && certificate.publicKey;

    return Boolean(
        privateKey &&
        privateKey.n &&
        privateKey.e &&
        publicKey &&
        publicKey.n &&
        publicKey.e &&
        privateKey.n.compareTo(publicKey.n) === 0 &&
        privateKey.e.compareTo(publicKey.e) === 0
    );
}

function renderError(container, message) {
    const lines = Array.isArray(message) ? message : [message];
    const error = document.createElement('span');

    error.className = 'error';
    for (const [index, line] of lines.entries()) {
        if (index > 0) {
            error.append(document.createElement('br'));
        }
        error.append(document.createTextNode(String(line)));
    }
    container.replaceChildren(error);
}

function reportError(container, context, error) {
    const message = `${context}: ${getErrorMessage(error)}`;

    logToPage(message);
    renderError(container, message);
    console.error(`${context}:`, error);
}

function resetGeneratedCertificate() {
    const button = document.getElementById('downloadButton');
    const output = document.getElementById('output');

    button.classList.add('hidden');
    button.onclick = null;
    output.classList.add('hidden');
    output.textContent = '';
}

function getCertificateBundleFilenames(hostname, filenames = []) {
    const bundlePrefix = `${hostname}_`;
    const suffixExtensions = new Map();

    for (const filename of filenames) {
        if (!filename.startsWith(bundlePrefix)) {
            continue;
        }

        const match = filename.slice(bundlePrefix.length).match(CA_BUNDLE_FILE_PATTERN);

        if (!match) {
            continue;
        }

        const [, suffix, extension] = match;

        if (!suffixExtensions.has(suffix)) {
            suffixExtensions.set(suffix, new Set());
        }
        suffixExtensions.get(suffix).add(extension);
    }

    const suffixes = [...suffixExtensions.keys()].sort().reverse();
    const completeSuffix = suffixes.find(suffix =>
        CA_BUNDLE_EXTENSIONS.every(extension =>
            suffixExtensions.get(suffix).has(extension)
        )
    );
    const suffix = completeSuffix || suffixes[0] || DEFAULT_CA_BUNDLE_SUFFIX;
    const certificate = `${hostname}_${suffix}.crt`;
    const key = `${hostname}_${suffix}.key`;
    const password = `${hostname}_${suffix}.txt`;
    const serial = `${hostname}.srl`;

    return {
        certificate,
        key,
        password,
        required: [certificate, key, password, serial],
        serial,
        suffix
    };
}

// UI for expected/missing/unexpected files
function initializeFileStatus() {
    const output = document.getElementById('output');
    const fileList = document.getElementById('fileList');
    const hostnameInput = document.getElementById('hostname');
    const filesInput = document.getElementById('files');
    function renderFileStatus() {
        const hostname = hostnameInput.value.trim() || hostnameInput.placeholder;
        const normHost = normalizeHostname(hostname);
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
                            output.classList.remove('hidden');
                            renderError(output, `Error reading zip: ${getErrorMessage(err)}`);
                            renderFileStatus.zipNames = [];
                            return;
                        }
                        let zipNames;
                        try {
                            zipNames = normalizeArchiveEntries(files).map(({ name }) => name);
                        } catch (error) {
                            output.classList.remove('hidden');
                            renderError(output, `Error reading zip: ${getErrorMessage(error)}`);
                            renderFileStatus.zipNames = [];
                            return;
                        }
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
                const bundle = getCertificateBundleFilenames(normHost, zipNames);

                renderFileLists(fileList, bundle.required, zipNames);
            }
        } else {
            // Clear zip cache if no zip is present
            renderFileStatus.lastZipName = undefined;
            renderFileStatus.lastZipSize = undefined;
            renderFileStatus.zipNames = undefined;
            // No zip, use uploaded files
            const uploadedNames = uploaded.map(f => f.name);
            const bundle = getCertificateBundleFilenames(normHost, uploadedNames);

            renderFileLists(fileList, bundle.required, uploadedNames);
        }
    }
    hostnameInput.addEventListener('input', renderFileStatus);
    filesInput.addEventListener('change', function() {
        // Hide and clear the output box when new files are selected
        output.classList.add('hidden');
        output.textContent = '';
        renderFileStatus();
    });
    renderFileStatus();
}

// main form submission logic
async function handleSubmit(e) {
    e.preventDefault();
    resetGeneratedCertificate();
    const output = document.getElementById('output');
    try {
        const hostname = document.getElementById('hostname').value.trim();
        const years = parseValidityYears(document.getElementById('years').value);
        const filesInput = document.getElementById('files');
        if (!hostname || !filesInput.files.length) {
            output.classList.remove('hidden');
            output.textContent = 'Please fill all fields and upload the required files.';
            return;
        }
        if (years === null) {
            output.classList.remove('hidden');
            output.textContent = 'Years until expiration must be a positive whole number.';
            return;
        }

        // No matter which hostname is entered, normalize to cert.staging.realm.customer.demandware.net
        const normHost = normalizeHostname(hostname);
        console.log(`Normalized Hostname: ${normHost}`);

        // Build fileMap from individual files
        const fileMap = createFileMap(filesInput.files);

        // If a zip is present, extract its files and add to fileMap
        const zipFile = Array.from(filesInput.files).find(f => f.name.endsWith('.zip'));
        if (zipFile) {
            fileMap.delete(zipFile.name);
            output.classList.remove('hidden');
            output.textContent = 'Extracting zip...';
            let buffer;
            try {
                buffer = await zipFile.arrayBuffer();
            } catch (err) {
                throw new Error(`Error reading zip file: ${getErrorMessage(err)}`);
            }
            await new Promise((resolve, reject) => {
                fflate.unzip(new Uint8Array(buffer), (err, files) => {
                    if (err) {
                        reject(new Error(`Error extracting zip: ${getErrorMessage(err)}`));
                        return;
                    }
                    try {
                        for (const { data, name } of normalizeArchiveEntries(files)) {
                            if (fileMap.has(name)) {
                                throw new Error(`Uploaded files contain multiple files named "${name}".`);
                            }
                            fileMap.set(name, new File([data], name));
                        }
                    } catch (error) {
                        reject(error);
                        return;
                    }
                    output.textContent = 'Zip extracted successfully.';
                    resolve();
                });
            });
        }

        const bundle = getCertificateBundleFilenames(normHost, [...fileMap.keys()]);
        const caCertFilename = bundle.certificate;
        const caKeyFilename = bundle.key;
        const caPassFilename = bundle.password;
        const caSerialFilename = bundle.serial;

        // Check for required files
        const missing = bundle.required.filter(filename => !fileMap.has(filename));
        if (missing.length) {
            output.classList.remove('hidden');
            renderError(output, ['Missing required file(s):', ...missing]);
            console.log(`Missing Files: ${missing.join(', ')}`);
            return;
        }

        output.classList.remove('hidden');
        output.textContent = 'Working...';
        console.log('All required files found. Starting PKI logic...');

        // --- PKI logic start ---
        try {
            function pemToPrivateKey(pem, password) {
                if (/Proc-Type: 4,ENCRYPTED/.test(pem) ||
                    /-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(pem)) {
                    return forge.pki.decryptRsaPrivateKey(pem, password);
                } else {
                    return forge.pki.privateKeyFromPem(pem);
                }
            }

            // 1. Read CA cert, key, password, serial
            // The CA serial from the .srl file cannot be incremented in the browser
            // Use the current Unix timestamp instead
            const readAsText = file => file.text();
            const [caCertPem, caKeyPem, caPassText, caSerialText] = await Promise.all([
                readAsText(fileMap.get(caCertFilename)),
                readAsText(fileMap.get(caKeyFilename)),
                readAsText(fileMap.get(caPassFilename)),
                readAsText(fileMap.get(caSerialFilename))
            ]);

            // 2. Get export password
            const exportPassword = document.getElementById('exportPassword').value;

            // 3. Parse CA cert and key
            logToPage('Parsing CA cert and key...');
            const caCertObj = forge.pki.certificateFromPem(caCertPem);
            if (!isCertificateAuthority(caCertObj)) {
                throw new Error(CA_CERTIFICATE_CANNOT_ISSUE_MESSAGE);
            }
            const caKeyObj = pemToPrivateKey(caKeyPem, getPasswordFileValue(caPassText));
            if (!caKeyObj) {
                throw new Error('Failed to parse/import CA private key.');
            }
            if (!rsaPrivateKeyMatchesCertificate(caKeyObj, caCertObj)) {
                throw new Error(CA_KEY_MISMATCH_MESSAGE);
            }
            const certificateValidity = getCertificateValidity(caCertObj, years);
            // 4. Generate user keypair and CSR
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
            // 5. Sign CSR to create user cert
            logToPage('Signing certificate...');
            const userCert = forge.pki.createCertificate();
            userCert.serialNumber = (Date.now()).toString();
            userCert.validity.notBefore = certificateValidity.notBefore;
            userCert.validity.notAfter = certificateValidity.notAfter;
            userCert.setSubject(csr.subject.attributes);
            userCert.setIssuer(caCertObj.subject.attributes);
            userCert.publicKey = userKeyPair.publicKey;
            userCert.setExtensions([
                { name: 'basicConstraints', cA: false }
            ]);
            userCert.sign(caKeyObj, forge.md.sha256.create());
            // 6. Export PKCS#12
            logToPage('Exporting PKCS#12 (.p12)...');
            // We use our own version of forge.pkcs12.toPkcs12Asn1 because Forge hardcodes sha1 for PKCS#12 MAC
            // https://github.com/digitalbazaar/forge/blob/2bb97afb5058285ef09bcf1d04d6bd6b87cffd58/lib/pkcs12.js#L796
            const p12Asn1 = createPkcs12Asn1(
                forge,
                userKeyPair.privateKey,
                [userCert, caCertObj],
                exportPassword,
                {
                    generateLocalKeyId: true,
                    friendlyName: userCN,
                    algorithm: 'aes256',
                    useMac: true,
                    macAlgorithm: 'sha256',
                    saltSize: DEFAULT_PKCS12_SALT_SIZE,
                    count: DEFAULT_PKCS12_ITERATION_COUNT
                }
            );
            const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
            const blob = new Blob([new Uint8Array([...p12Der].map(c => c.charCodeAt(0)))], { type: 'application/x-pkcs12' });
            // Create a green download button with save.svg icon
            const button = document.getElementById('downloadButton');
            button.classList.remove('hidden');
            button.onclick = function() {
                // Use email address up to @ for filename prefix
                const emailPrefix = email.split('@')[0];
                const filename = `${emailPrefix}-${normHost}.p12`;
                // Append and click a link to trigger the download, then revoke the object URL to release memory
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = filename;
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
            reportError(output, ERROR_CONTEXTS.certificateGeneration, err);
        }
    } catch (err) {
        reportError(output, ERROR_CONTEXTS.fileProcessing, err);
    }
}

if (typeof document !== 'undefined') {
    const form = document.getElementById('certForm');

    initializeFileStatus();
    form.addEventListener('input', resetGeneratedCertificate);
    form.addEventListener('change', resetGeneratedCertificate);
    form.addEventListener('submit', handleSubmit);
}

/**
 * A version of forge.pkcs12.toPkcs12Asn1 that allows specifying the MAC algorithm
 * Also encrypts the certificate chain, not just the private key
 *
 * @param forge the Forge API
 * @param key the private key
 * @param cert the certificate (may be an array of certificates in order
 *          to specify a certificate chain)
 * @param password the password to use, null for none
 * @param options:
 *          algorithm the encryption algorithm to use
 *            ('aes128', 'aes192', 'aes256', '3des'), defaults to 'aes128'
 *          macAlgorithm the MAC algorithm to use
 *            ('sha1', 'sha256', 'sha384', 'sha512'), defaults to 'sha1'
 *          count the iteration count to use
 *          saltSize the salt size to use
 *          useMac true to include a MAC, false not to, defaults to true
 *          localKeyId the local key ID to use, in hex
 *          friendlyName the friendly name to use
 *          generateLocalKeyId true to generate a random local key ID,
 *            false not to, defaults to true
 *
 * @return the PKCS#12 PFX ASN.1 object
 */
function createPkcs12Asn1(forge, key, cert, password, options) {
    const asn1 = forge.asn1;
    const pki = forge.pki;
    const p12 = forge.pkcs12;
    // set default options
    options = { ...(options || {}) };
    options.saltSize = options.saltSize ?? DEFAULT_PKCS12_SALT_SIZE;
    options.count = options.count ?? DEFAULT_PKCS12_ITERATION_COUNT;
    options.algorithm = options.algorithm || options.encAlgorithm || 'aes128';
    validatePositiveIntegerOption('count', options.count);
    validatePositiveIntegerOption('saltSize', options.saltSize);
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

        // Used to encrypt the cert chain, while only the private key is encrypted by default
        // It's unusual to encrypt more than the private key, but that is what the openssl
        // commands we are mimicking do
        function encryptSafeContentsAsEncryptedData(safeContentsBytes, password, options) {
            options = options || {};
            const saltSize = options.saltSize;
            const count = options.count;
            const prf = (options.macAlgorithm || 'sha256').toLowerCase();
            const algorithm = (options.algorithm || 'aes256').toLowerCase();

            const prfOid = {
                sha1: forge.pki.oids.hmacWithSHA1,
                sha256: forge.pki.oids.hmacWithSHA256,
                sha384: forge.pki.oids.hmacWithSHA384,
                sha512: forge.pki.oids.hmacWithSHA512
            }[prf];
            if (!prfOid) throw new Error(`Unsupported PRF algorithm: ${prf}`);

            const encryptionSettings = {
                aes128: {
                    cipher: 'AES-CBC',
                    ivSize: 16,
                    keySize: 16,
                    oid: forge.pki.oids['aes128-CBC']
                },
                aes192: {
                    cipher: 'AES-CBC',
                    ivSize: 16,
                    keySize: 24,
                    oid: forge.pki.oids['aes192-CBC']
                },
                aes256: {
                    cipher: 'AES-CBC',
                    ivSize: 16,
                    keySize: 32,
                    oid: forge.pki.oids['aes256-CBC']
                },
                '3des': {
                    cipher: '3DES-CBC',
                    ivSize: 8,
                    keySize: 24,
                    oid: forge.pki.oids['des-EDE3-CBC']
                }
            }[algorithm];
            if (!encryptionSettings) {
                throw new Error(`Unsupported algorithm: ${algorithm}`);
            }

            const salt = forge.random.getBytes(saltSize);
            const iv = forge.random.getBytes(encryptionSettings.ivSize);
            const key = forge.pkcs5.pbkdf2(
                password,
                salt,
                count,
                encryptionSettings.keySize,
                forge.md[prf].create()
            );

            const cipher = forge.cipher.createCipher(encryptionSettings.cipher, key);
            cipher.start({ iv });
            cipher.update(forge.util.createBuffer(safeContentsBytes));
            if (!cipher.finish()) {
                throw new Error('Failed to encrypt certificate contents.');
            }
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
                        forge.asn1.oidToDer(encryptionSettings.oid).getBytes()),
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
                md = forge.md.sha1.create();
                oid = pki.oids.sha1;
                keyLen = 20;
                break;
            default:
                throw new Error(`Unsupported MAC algorithm: ${digestAlgorithm}`);
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
}

// Normalizes a Business Manager hostname to the format cert.staging.realm.customer.demandware.net
function normalizeHostname(hostname) {
    return hostname.replace(/[_-]/g, '.')
        .replace(/^(production\.|development\.|staging\.|cert\.staging\.)/, '')
        .replace(/\.demandware\.net$/, '')
        .replace(/^/, 'cert.staging.')
        .replace(/$/, '.demandware.net');
}

// Adds a line of text to the "console" on the page
function logToPage(msg) {
    const log = document.getElementById('console-log');
    log.textContent += (msg + '\n');
    log.scrollTop = log.scrollHeight;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        createPkcs12Asn1,
        createFileMap,
        getCertificateBundleFilenames,
        getCertificateValidity,
        getErrorMessage,
        getPasswordFileValue,
        isCertificateAuthority,
        normalizeArchiveEntries,
        parseValidityYears,
        renderError,
        renderFileLists,
        resetGeneratedCertificate,
        rsaPrivateKeyMatchesCertificate
    };
}
