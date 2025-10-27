// interactive_derive_keplr.js
// Interaktif: selalu tanya mnemonic di terminal (input tersembunyi).
// Usage: node interactive_derive_keplr.js [--prefix=<prefix>] [--path="<derivation path>"]
// Contoh: node interactive_derive_keplr.js --prefix=osmo --path="m/44'/118'/0'/0/0"

const promptSync = require('prompt-sync');
const bip39 = require('bip39');
const BIP32Factory = require('bip32').BIP32Factory;
const ecc = require('tiny-secp256k1');
const { bech32 } = require('bech32');
const Ripemd160 = require('ripemd160');
const crypto = require('crypto');

const prompt = promptSync({ sigint: true });

// Inisialisasi bip32 dengan tiny-secp256k1
const bip32 = BIP32Factory(ecc);

// helper
function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

function ripemd160(buf) {
  return new Ripemd160().update(buf).digest();
}

function bech32AddressFromPubkey(pubkeyCompressed, prefix) {
  const h = ripemd160(sha256(pubkeyCompressed));
  const words = bech32.toWords(h);
  return bech32.encode(prefix, words);
}

// baca arg sederhana
const argv = require('minimist')(process.argv.slice(2));
const derivationPath = argv.path || "m/44'/118'/0'/0/0";
const prefix = argv.prefix || 'cosmos';

console.log('=== Keplr-style key derivation (interactive) ===');
console.log(`Derivation path (default): ${derivationPath}`);
console.log(`Bech32 prefix (default): ${prefix}`);
console.log('-------------------------------------------------');

// tanya mnemonic (input tersembunyi)
const mnemonic = prompt('Masukkan mnemonic (seed phrase): ', { echo: '*' });

if (!mnemonic || typeof mnemonic !== 'string' || mnemonic.trim().length === 0) {
  console.error('Error: mnemonic kosong. Keluar.');
  process.exit(1);
}

const trimmed = mnemonic.trim();
if (!bip39.validateMnemonic(trimmed)) {
  console.error('Error: mnemonic tidak valid. Periksa jumlah kata / ejaan.');
  process.exit(2);
}

(async () => {
  try {
    const seed = await bip39.mnemonicToSeed(trimmed); // Buffer
    const root = bip32.fromSeed(seed);
    const child = root.derivePath(derivationPath);

    if (!child || !child.privateKey) {
      console.error('Error: privateKey tidak ditemukan pada path derivasi yang diberikan.');
      process.exit(3);
    }

    const privateKey = child.privateKey; // Buffer 32 bytes
    const pubkeyCompressed = Buffer.from(ecc.pointFromScalar(privateKey, true)); // 33 bytes compressed
    const address = bech32AddressFromPubkey(pubkeyCompressed, prefix);

    console.log('\n=== Hasil derivasi ===');
    console.log('Derivation path :', derivationPath);
    console.log('Bech32 prefix   :', prefix);
    console.log('Address         :', address);
    console.log('Private key (hex):', privateKey.toString('hex'));
    console.log('Public key (hex) :', pubkeyCompressed.toString('hex'));
    console.log('======================');
  } catch (err) {
    console.error('Error:', err.message || err);
    process.exit(99);
  }
})();
