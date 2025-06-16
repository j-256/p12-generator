// main.js
// This file will handle UI logic and certificate generation
// Placeholder for now. Will add OpenSSL/WASM logic next.
document.getElementById('certForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const output = document.getElementById('output');
    output.textContent = '';
    try {
        const hostname = document.getElementById('hostname').value.trim();
        const years = parseInt(document.getElementById('years').value, 10);
        const filesInput = document.getElementById('files');
        if (!hostname || !years || !filesInput.files.length) {
            output.textContent = 'Please fill all fields and upload the required files.';
            return;
        }

        // Helper: normalize hostname as in the bash script
        function normalizeHostname(h) {
            return h.replace(/[_-]/g, '.')
                .replace(/^(production\.|development\.|staging\.|cert\.staging\.)/, '')
                .replace(/\.demandware\.net$/, '')
                .replace(/^/, 'cert.staging.')
                .replace(/$/, '.demandware.net');
        }
        const normHost = normalizeHostname(hostname);

        // Required filenames
        const caCert = `${normHost}_01.crt`;
        const caKey = `${normHost}_01.key`;
        const caPass = `${normHost}_01.txt`;
        const caSerial = `${normHost}.srl`;
        const requiredFiles = [caCert, caKey, caPass, caSerial];

        // Build fileMap from individual files
        let fileMap = {};
        for (let file of filesInput.files) {
            fileMap[file.name] = file;
        }
        // If a zip is present, extract its files and add to fileMap
        const zipFile = Array.from(filesInput.files).find(f => f.name.endsWith('.zip'));
        if (zipFile) {
            output.textContent = 'Extracting zip...';
            let buf;
            try {
                buf = await zipFile.arrayBuffer();
            } catch (err) {
                output.innerHTML = `<span style='color:red'>Error reading zip file: ${err.message || JSON.stringify(err)}</span>`;
                throw err;
            }
            await new Promise((resolve, reject) => {
                fflate.unzip(new Uint8Array(buf), (err, files) => {
                    if (err) {
                        output.innerHTML = `<span style='color:red'>Error extracting zip: ${err.message || JSON.stringify(err)}</span>`;
                        reject(err);
                        return;
                    }
                    for (let [name, data] of Object.entries(files)) {
                        fileMap[name] = new File([data], name);
                    }
                    resolve();
                });
            });
        }

        // Check for required files
        const missing = requiredFiles.filter(f => !(f in fileMap));
        if (missing.length) {
            output.innerHTML = `<span style='color:red'>Missing required file(s):<br>${missing.join('<br>')}</span>`;
            return;
        }

        output.innerHTML = `<b>All required files found.</b><br>Generating .p12 (in-browser)...`;

        // --- PKI logic start ---
        try {
            function logToConsole(msg) {
                const log = document.getElementById('console-log');
                log.textContent += (msg + '\n');
                log.scrollTop = log.scrollHeight;
            }
            // PEM to forge object utility
            function pemToCert(pem) {
                return forge.pki.certificateFromPem(pem);
            }
            function pemToPrivateKey(pem, password) {
                if (/Proc-Type: 4,ENCRYPTED/.test(pem)) {
                    return forge.pki.decryptRsaPrivateKey(pem, password);
                } else {
                    return forge.pki.privateKeyFromPem(pem);
                }
            }
            // 1. Read CA cert, key, password, serial
            const readAsText = file => file.text();
            const [caCertPem, caKeyPem, caPassText, caSerialText] = await Promise.all([
                readAsText(fileMap[caCert]),
                readAsText(fileMap[caKey]),
                readAsText(fileMap[caPass]),
                readAsText(fileMap[caSerial])
            ]);

            // 2. Prompt for export password
            let exportPassword = prompt("Enter export password for .p12 (will be required to use the certificate):");
            if (!exportPassword) {
                output.innerHTML = '<span style="color:red">Export password is required.</span>';
                return;
            }

            // 3. Generate user keypair and CSR
            logToConsole('Generating keypair and CSR...');
            const userKeyPair = forge.pki.rsa.generateKeyPair(2048);
            // Subject info
            const userCN = hostname;
            const csr = forge.pki.createCertificationRequest();
            csr.publicKey = userKeyPair.publicKey;
            csr.setSubject([{ name: 'commonName', value: userCN }]);
            csr.sign(userKeyPair.privateKey, forge.md.sha256.create());

            // 4. Parse CA cert and key
            logToConsole('Parsing CA cert and key...');
            const caCertObj = pemToCert(caCertPem);
            let caKeyObj = pemToPrivateKey(caKeyPem, caPassText.trim());
            if (!caKeyObj) {
                logToConsole('Failed to parse/import CA private key.');
                output.innerHTML = `<span style='color:red'>Failed to parse/import CA private key.</span>`;
                throw new Error('Failed to parse/import CA private key.');
            }

            // 5. Sign CSR to create user cert
            logToConsole('Signing certificate...');
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

            // 6. Export PKCS#12
            logToConsole('Exporting PKCS#12 (.p12)...');
            const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
                userKeyPair.privateKey,
                [userCert, caCertObj],
                exportPassword,
                { generateLocalKeyId: true, friendlyName: userCN }
            );
            const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
            const blob = new Blob([new Uint8Array([...p12Der].map(c => c.charCodeAt(0)))], { type: 'application/x-pkcs12' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `${userCN}.p12`;
            a.textContent = 'Download .p12';
            output.innerHTML += '<br>';
            output.appendChild(a);
            logToConsole('Done.');
        } catch (err) {
            logToConsole('Error during certificate generation: ' + (err.message || JSON.stringify(err)));
            output.innerHTML = `<span style='color:red'>Error during certificate generation: ${err.message || JSON.stringify(err)}</span>`;
            console.error('Error during certificate generation:', err);
            throw err;
        }
    } catch (err) {
        output.innerHTML = `<span style='color:red'>Unexpected error: ${err.message || JSON.stringify(err)}</span>`;
        throw err;
    }
});

document.getElementById('files').addEventListener('change', async function() {
    const output = document.getElementById('output');
    output.textContent = '';
    let fileList = [];
    let fileMap = {};
    for (let file of this.files) {
        fileMap[file.name] = file;
    }
    const zipFile = Array.from(this.files).find(f => f.name.endsWith('.zip'));
    if (zipFile) {
        output.textContent = 'Reading zip...';
        let buf;
        try {
            buf = await zipFile.arrayBuffer();
        } catch (err) {
            output.innerHTML = `<span style='color:red'>Error reading zip file: ${err.message || JSON.stringify(err)}</span>`;
            throw err;
        }
        fflate.unzip(new Uint8Array(buf), (err, files) => {
            if (err) {
                output.innerHTML = `<span style='color:red'>Error reading zip file: ${err.message || JSON.stringify(err)}</span>`;
                throw err;
            }
            fileList = Object.keys(files);
            if (fileList.length) {
                let details = fileList.map(f => {
                    const meta = files[f];
                    let sizeInfo = '';
                    if (meta.compressedSize !== undefined && meta.originalSize !== undefined) {
                        sizeInfo = `<small>(compressed: ${meta.compressedSize} bytes, uncompressed: ${meta.originalSize} bytes)</small>`;
                    }
                    return `<li>${f} ${sizeInfo}</li>`;
                }).join('');
                output.innerHTML = `<b>Files detected in zip:</b><br><ul style='margin-top:0.5em'>${details}</ul>`;
            } else {
                output.innerHTML = `<span style='color:red'>No files detected in zip.</span>`;
            }
        });
    } else {
        fileList = Object.keys(fileMap);
        if (fileList.length) {
            output.innerHTML = `<b>Files detected:</b><br><ul style='margin-top:0.5em'>${fileList.map(f => `<li>${f}</li>`).join('')}</ul>`;
        } else {
            output.textContent = 'No files detected.';
        }
    }
});
