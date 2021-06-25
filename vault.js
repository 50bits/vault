const vaultCypherType = {
    AES_256: 1,
    RSA_4096: 2
};

class VaultUtil {
    fromUtf8(str) {
        const strUtf8 = unescape(encodeURIComponent(str));
        const bytes = new Uint8Array(strUtf8.length);
        for (let i = 0; i < strUtf8.length; i++) {
            bytes[i] = strUtf8.charCodeAt(i);
        }
        return bytes.buffer;
    }

    toUtf8(buf) {
        const bytes = new Uint8Array(buf);
        const encodedString = String.fromCharCode.apply(null, bytes);
        return decodeURIComponent(escape(encodedString));
    }

    toB64(buf) {
        if (!buf) return;
        let binary = '';
        const bytes = new Uint8Array(buf);
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    fromB64(base64) {
        if (!base64) return;
        try {
            const binary_string = window.atob(base64);
            const len = binary_string.length;
            let bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = binary_string.charCodeAt(i);
            }
            return bytes.buffer;
        } catch (err) {
            alert("Check your message part: " + base64);
            return new Uint8Array(1);
        }
    }

    toHex(dec) {
        return Number(dec).toString(16);
    }
}
let vaultUtil = new VaultUtil();

/**
 * CRC16-CCITT
 */
class VaultChecksum {
    initValue = 0xFFFF;

    crcTable = [0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5,
        0x60c6, 0x70e7, 0x8108, 0x9129, 0xa14a, 0xb16b,
        0xc18c, 0xd1ad, 0xe1ce, 0xf1ef, 0x1231, 0x0210,
        0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
        0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c,
        0xf3ff, 0xe3de, 0x2462, 0x3443, 0x0420, 0x1401,
        0x64e6, 0x74c7, 0x44a4, 0x5485, 0xa56a, 0xb54b,
        0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
        0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6,
        0x5695, 0x46b4, 0xb75b, 0xa77a, 0x9719, 0x8738,
        0xf7df, 0xe7fe, 0xd79d, 0xc7bc, 0x48c4, 0x58e5,
        0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
        0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969,
        0xa90a, 0xb92b, 0x5af5, 0x4ad4, 0x7ab7, 0x6a96,
        0x1a71, 0x0a50, 0x3a33, 0x2a12, 0xdbfd, 0xcbdc,
        0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
        0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03,
        0x0c60, 0x1c41, 0xedae, 0xfd8f, 0xcdec, 0xddcd,
        0xad2a, 0xbd0b, 0x8d68, 0x9d49, 0x7e97, 0x6eb6,
        0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
        0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a,
        0x9f59, 0x8f78, 0x9188, 0x81a9, 0xb1ca, 0xa1eb,
        0xd10c, 0xc12d, 0xf14e, 0xe16f, 0x1080, 0x00a1,
        0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c,
        0xe37f, 0xf35e, 0x02b1, 0x1290, 0x22f3, 0x32d2,
        0x4235, 0x5214, 0x6277, 0x7256, 0xb5ea, 0xa5cb,
        0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
        0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447,
        0x5424, 0x4405, 0xa7db, 0xb7fa, 0x8799, 0x97b8,
        0xe75f, 0xf77e, 0xc71d, 0xd73c, 0x26d3, 0x36f2,
        0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
        0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9,
        0xb98a, 0xa9ab, 0x5844, 0x4865, 0x7806, 0x6827,
        0x18c0, 0x08e1, 0x3882, 0x28a3, 0xcb7d, 0xdb5c,
        0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
        0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0,
        0x2ab3, 0x3a92, 0xfd2e, 0xed0f, 0xdd6c, 0xcd4d,
        0xbdaa, 0xad8b, 0x9de8, 0x8dc9, 0x7c26, 0x6c07,
        0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
        0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba,
        0x8fd9, 0x9ff8, 0x6e17, 0x7e36, 0x4e55, 0x5e74,
        0x2e93, 0x3eb2, 0x0ed1, 0x1ef0];

    crc16(str) {
        let crc = this.initValue;
        for (let i = 0; i < str.length; i++) {
            let c = str.charCodeAt(i);
            if (c > 255) {
                throw new RangeError();
            }
            let j = (c ^ (crc >> 8)) & 0xFF;
            crc = this.crcTable[j] ^ (crc << 8);
        }
        return ((crc ^ 0) & 0xFFFF);
    }
}
let vaultChecksum = new VaultChecksum();

class VaultCypher {
    constructor(str) {
        if (!str) return;
        let obj = JSON.parse(str);
        this.type = parseInt(obj.type);
        this.time = obj.time;
        this.key = vaultUtil.fromB64(obj.key);
        this.salt = vaultUtil.fromB64(obj.salt);
        this.iv = vaultUtil.fromB64(obj.iv);
        this.data = vaultUtil.fromB64(obj.data);
    }

    stringify() {
        let obj = {};
        obj.type = this.type;
        obj.time = this.time;
        obj.key = vaultUtil.toB64(this.key);
        obj.salt = vaultUtil.toB64(this.salt);
        obj.iv = vaultUtil.toB64(this.iv);
        obj.data = vaultUtil.toB64(this.data);
        return JSON.stringify(obj);
    }
}

/**
 * Web Crypto API
 */
class VaultCrypto {
    isCypher(str) {
        if (!str) return false;
        try {
            new VaultCypher(str);
            return true;
        } catch (err) {
            return false;
        }
    }

    async aesImportAndDeriveKey(password, salt) {
        let key = await window.crypto.subtle.importKey(
            "raw",
            vaultUtil.fromUtf8(password),
            {
                name: "PBKDF2"
            },
            false,
            ["deriveKey"]
        );
        return window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 1000000,
                hash: { name: "SHA-256" }
            },
            key,
            {
                name: "AES-CBC",
                length: 256
            },
            false,
            ["encrypt", "decrypt"]
        );
    }

    async aesGenerateAndExportKey() {
        let key = await window.crypto.subtle.generateKey(
            {
                name: "AES-CBC",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
        return window.crypto.subtle.exportKey(
            "jwk",
            key
        );
    }

    async aesImportKey(key) {
        return window.crypto.subtle.importKey(
            "jwk",
            key,
            {
                name: "AES-CBC"
            },
            false,
            ["encrypt", "decrypt"]
        );
    }

    async aesEncrypt(key, iv, str) {
        return await window.crypto.subtle.encrypt(
            {
                name: "AES-CBC",
                iv: iv
            },
            key,
            vaultUtil.fromUtf8(str)
        );
    }

    async aesDecrypt(key, iv, data) {
        return await window.crypto.subtle.decrypt(
            {
                name: "AES-CBC",
                iv: iv
            },
            key,
            data
        );
    }

    async rsaImportPublicKey(publicKey) {
        return await window.crypto.subtle.importKey(
            "jwk",
            publicKey,
            {
                name: "RSA-OAEP",
                hash: { name: "SHA-256" }
            },
            false,
            ["encrypt"]
        );
    }

    async rsaImportPrivateKey(privateKey) {
        return await window.crypto.subtle.importKey(
            "jwk",
            privateKey,
            {
                name: "RSA-OAEP",
                hash: { name: "SHA-256" }
            },
            false,
            ["decrypt"]
        );
    }

    async rsaEncrypt(publicKey, str) {
        return await window.crypto.subtle.encrypt(
            {
                name: "RSA-OAEP"
            },
            publicKey,
            vaultUtil.fromUtf8(str)
        );
    }

    async rsaDecrypt(privateKey, data) {
        return await window.crypto.subtle.decrypt(
            {
                name: "RSA-OAEP"
            },
            privateKey,
            data
        );
    }

    async aesEncryptFlow(password, message) {
        let cypher = new VaultCypher();
        cypher.type = vaultCypherType.AES_256;
        cypher.salt = window.crypto.getRandomValues(new Uint8Array(16));
        cypher.iv = window.crypto.getRandomValues(new Uint8Array(16));
        let key = await this.aesImportAndDeriveKey(password, cypher.salt);
        cypher.data = await this.aesEncrypt(key, cypher.iv, message);
        return cypher.stringify();
    }

    async aesDecryptFlow(password, cypher) {
        let key = await this.aesImportAndDeriveKey(password, cypher.salt);
        return vaultUtil.toUtf8(await this.aesDecrypt(key, cypher.iv, cypher.data));
    }

    async rsaEncryptFlow(publicKey, message, time) {
        let cypher = new VaultCypher();
        cypher.type = vaultCypherType.RSA_4096;
        cypher.time = time;
        let aesKey = await this.aesGenerateAndExportKey();
        let importedPublicKey = await this.rsaImportPublicKey(publicKey);
        cypher.key = await this.rsaEncrypt(importedPublicKey, JSON.stringify(aesKey));
        let importedAesKey = await this.aesImportKey(aesKey);
        cypher.iv = window.crypto.getRandomValues(new Uint8Array(16));
        cypher.data = await this.aesEncrypt(importedAesKey, cypher.iv, message);
        return cypher.stringify();
    }

    async rsaDecryptFlow(privateKey, cypher) {
        let importedPrivateKey = await this.rsaImportPrivateKey(privateKey);
        let aesKey = JSON.parse(vaultUtil.toUtf8(await this.rsaDecrypt(importedPrivateKey, cypher.key)));
        let importedAesKey = await this.aesImportKey(aesKey);
        return vaultUtil.toUtf8(await this.aesDecrypt(importedAesKey, cypher.iv, cypher.data));
    }

    async autoCryptFlow(password, message, time) {
        try {
            let cypher = new VaultCypher(message);
            if (cypher.type == vaultCypherType.AES_256) {
                return await this.aesDecryptFlow(password, cypher);
            } else if (cypher.type == vaultCypherType.RSA_4096) {
                const privateKey = vaultKeys[cypher.time].privateKey;
                if (!privateKey) {
                    alert("Message cannot be unlocked before year " + cypher.time);
                    return message;
                }
                return await this.rsaDecryptFlow(privateKey, cypher);
            }
        } catch (err) {
            if (time) {
                const publicKey = vaultKeys[time].publicKey
                return await this.rsaEncryptFlow(publicKey, message, time);
            } else {
                return await this.aesEncryptFlow(password, message);
            }
        }
        return message;
    }
}
let vaultCrypto = new VaultCrypto();

class VaultMainController {
    applyTimeLock = false;

    constructor(printView, mainView, timelockCheckbox, yearSelect, passwordField, checksumElement, lockButton, copyButton, printButton, clearButton, messageField, messageLengthElement) {
        this.printView = printView;
        this.mainView = mainView;
        this.timelockCheckbox = timelockCheckbox;
        this.yearSelect = yearSelect;
        this.passwordField = passwordField;
        this.checksumElement = checksumElement;
        this.lockButton = lockButton;
        this.copyButton = copyButton;
        this.printButton = printButton;
        this.clearButton = clearButton;
        this.messageField = messageField;
        this.messageLengthElement = messageLengthElement;
    }

    updateVisibility() {
        this.timelockCheckbox.checked = this.applyTimeLock;
        this.yearSelect.disabled = !this.applyTimeLock;
        this.passwordField.disabled = this.applyTimeLock;
        this.lockButton.disabled = (!this.applyTimeLock && !this.passwordField.value && !vaultCrypto.isCypher(this.messageField.value)) || !this.messageField.value;
        this.copyButton.disabled = !vaultCrypto.isCypher(this.messageField.value);
        this.printButton.disabled = !vaultCrypto.isCypher(this.messageField.value);
        this.clearButton.disabled = !this.messageField.value;
    }

    toggleApplyTimeLock() {
        this.applyTimeLock = !this.applyTimeLock;
        this.updateVisibility();
    }

    toggleShowPassword() {
        if (this.passwordField.type === "password") {
            this.passwordField.type = "text";
        } else {
            this.passwordField.type = "password";
        }
    }

    checksum(str) {
        let checksum;
        try {
            checksum = vaultUtil.toHex(vaultChecksum.crc16(str));
        } catch (err) {
            checksum = vaultUtil.toHex(0);
        }
        return checksum;
    }

    calcPasswordChecksum() {
        let passwordChecksum = this.checksum(this.passwordField.value);
        this.checksumElement.textContent = passwordChecksum.toUpperCase();
        this.updateVisibility();
    }

    countMessage() {
        this.messageLengthElement.textContent = this.messageField.value.length;
        this.updateVisibility();
    }

    setAndCountMessage(str) {
        this.messageField.value = str;
        this.countMessage();
    }

    appendAndCountMessage(str) {
        this.setAndCountMessage(this.messageField.value + str);
    }

    async cryptMessage() {
        const password = this.passwordField.value;
        let message = this.messageField.value;
        if (!message) return;
        let time;
        if (this.applyTimeLock) {
            time = this.yearSelect.value;
        }
        let cryptResult = await vaultCrypto.autoCryptFlow(password, message, time);
        this.setAndCountMessage(cryptResult);
    }

    copyMessage() {
        if (this.messageField.value === "") return;
        this.messageField.select();
        this.messageField.setSelectionRange(0, 99999);
        document.execCommand("copy");
    }

    printMessage() {
        this.printView.textContent = this.messageField.value;
        this.mainView.textContent = "";
    }
}

class VaultKeyboardController {
    capsLock = false;

    constructor(vaultMainController, capsLockButton) {
        this.vaultMainController = vaultMainController;
        this.capsLockButton = capsLockButton;
    }

    press(key) {
        if (key === "^") {
            this.capsLock = !this.capsLock;
            if (this.capsLock) {
                this.capsLockButton.style.cssText = "background-color: #70d3d4";
            } else {
                this.capsLockButton.style.cssText = "";
            }
            return;
        }
        if (this.capsLock) {
            key = key.toUpperCase();
        }
        this.vaultMainController.appendAndCountMessage(key);
    }
}