let generatedVaultKeys = {};

// step 1
function generateVaultKeys() {
    let years = ["2021", "2022"];
    let months = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"];
    years.forEach(function (y) {
        months.forEach(function (m) {
            generatedVaultKeys[m + "/" + y] = {};
            window.crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                    hash: { name: "SHA-256" },
                },
                true,
                ["encrypt", "decrypt"]
            ).then(function (keyPair) {
                window.crypto.subtle.exportKey("jwk", keyPair.publicKey).then(function (publicKey) {
                    generatedVaultKeys[m + "/" + y].publicKey = publicKey;
                });
                window.crypto.subtle.exportKey("jwk", keyPair.privateKey).then(function (privateKey) {
                    generatedVaultKeys[m + "/" + y].privateKey = privateKey;
                });
            });
        });
    });
}

// step 2
function printVaultKeys() {
    console.log(JSON.stringify(generatedVaultKeys));
}