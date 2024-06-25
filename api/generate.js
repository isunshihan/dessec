const { execSync } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');

function commandExists(command) {
    try {
        execSync(`${command} -h`, { stdio: 'ignore' });
        return true;
    } catch (error) {
        return false;
    }
}

function generateDnskey(domain) {
    if (!commandExists('/usr/sbin/dnssec-keygen')) {
        throw new Error('dnssec-keygen command not found. Make sure Bind9 utilities are installed and in your PATH.');
    }
    const command = `/usr/sbin/dnssec-keygen -a RSASHA256 -b 2048 -n ZONE ${domain}`;
    execSync(command, { stdio: 'inherit' });
}

function getPublicKey(domain) {
    const keyFiles = fs.readdirSync('.').filter(f => f.startsWith(`K${domain}`) && f.endsWith('.key'));
    if (keyFiles.length === 0) {
        throw new Error("DNSKEY file not found.");
    }
    const keyFile = keyFiles[0];
    const lines = fs.readFileSync(keyFile, 'utf-8').split('\n');
    const publicKey = lines.slice(1).join('').trim();
    return publicKey;
}

function getKeyTag(domain) {
    if (!commandExists('/usr/sbin/dnssec-dsfromkey')) {
        throw new Error('dnssec-dsfromkey command not found. Make sure Bind9 utilities are installed and in your PATH.');
    }
    const keyFiles = fs.readdirSync('.').filter(f => f.startsWith(`K${domain}`) && f.endsWith('.key'));
    if (keyFiles.length === 0) {
        throw new Error("DNSKEY file not found.");
    }
    const keyFile = keyFiles[0];
    const command = `/usr/sbin/dnssec-dsfromkey -2 ${keyFile}`;
    const output = execSync(command, { encoding: 'utf-8' }).split(/\s+/);
    const keyTag = output[3];
    if (!/^\d+$/.test(keyTag)) {
        throw new Error(`Invalid key tag value: ${keyTag}`);
    }
    return parseInt(keyTag, 10);
}

function generateDsRecord(domain, publicKey) {
    const digest = crypto.createHash('sha256').update(publicKey, 'utf-8').digest('hex').toUpperCase();
    return digest;
}

module.exports = (req, res) => {
    const { domain } = req.body;
    try {
        generateDnskey(domain);
        const publicKey = getPublicKey(domain);
        const keyTag = getKeyTag(domain);
        const digest = generateDsRecord(domain, publicKey);

        const algorithm = 8;  // RSASHA256
        const digestType = 2;  // SHA-256

        res.json({
            domain,
            keyTag,
            algorithm,
            digestType,
            digest
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};
