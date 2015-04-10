# OpenPGP.js-examples
A place to share your OpenPGP.js examples with comments to help build this into the largest library of its kind.

As developers, we know how frustrating it is to research complex algorithms. Often, you have to filter through many sites to find what you need. Well, we'd like to fix that. I'm starting off this library with some routines that I use here at fastdata2go.com to get things started. 

Please feel free to add to this library. I only ask that you follow these guidlines:
- Follow this format.
- Be current with the latest OpenPGP.js release.

####Generate Keypair
```javascript
	/**
	* Generate a Private and Public keypair
	* @param  {numBits} Integer - Any multiple of 1024. 2048 is recommended.
	* @param  {userid} String - should be like: Alice Mayfield <amayfield@quantum.com>
	* @param  {passphrase} String - password should be a 4-5 word sentence (20+ chars)
	* @return {key} String - Encrypted ASCII armored keypair (contains both Private and Public keys)
	*/
	function keygen(numBits, userId, passphrase) {
    var openpgp = window.openpgp;
    var key = openpgp.generateKeyPair({
        numBits: numBits,
        userId: userId,
        passphrase: passphrase
    });
    return key;
}
```



####Encrypt Message
```javascript
/**
 * Encrypt a message using the recipient's public key.
 * @param  {pubkey} String - Encrypted ASCII Armored public key.
 * @param  {message} String - Your message to the recipient.
 * @return {pgpMessage} String - Encrypted ASCII Armored message.
 */

function encrypt_message(pubkey, message) {
    var openpgp = window.openpgp;
    var key = pubkey;
    var publicKey = openpgp.key.readArmored(key);
    var pgpMessage = openpgp.encryptMessage(publicKey.keys, message);
    return pgpMessage;
}
```



####Decrypt Message
```javascript
/**
 * Decrypt a message using your private key.
 * @param  {pubkey} String - Your recipient's public key.
 * @param  {privkey} String - Your private key.
 * @param  {passphrase} String - Your ultra-strong password.
 * @param  {encoded_message} String - Your message from the recipient.
 * @return {decrypted} String - Decrypted message.
 */

function decrypt_message(pubkey, privkey, passphrase, encoded_message) {
    var openpgp = window.openpgp;
    var privKeys = openpgp.key.readArmored(privkey);
    var publicKeys = openpgp.key.readArmored(pubkey);
    var privKey = privKeys.keys[0];
    var success = privKey.decrypt(passphrase);
    var message = openpgp.message.readArmored(encoded_message);
    var decrypted = openpgp.decryptMessage(privKey, message);
    return decrypted;
}
```


####Sign Message
```javascript
/**
 * Sign a message using your private key.
 * @param  {pubkey} String - Your recipient's public key.
 * @param  {privkey} String - Your private key.
 * @param  {passphrase} String - Your ultra-strong password.
 * @param  {message} String - Your message from the recipient.
 * @return {signed} String - Signed message.
 */

function sign_message(pubkey, privkey, passphrase, message){
	var openpgp = window.openpgp;
	var priv = openpgp.key.readArmored(privkey);
	var pub = openpgp.key.readArmored(pubkey);
	var privKey = priv.keys[0];
	var success = priv.decrypt(passphrase);
	var signed = openpgp.signClearMessage(priv.keys, message);
	return signed;  
	}
```


####Verify Signature
```javascript
/**
 * Sign a message using your private key.
 * @param  {pubkey} String - Your recipient's public key.
 * @param  {privkey} String - Your private key.
 * @param  {passphrase} String - Your ultra-strong password.
 * @param  {signed_message} String - Your signed message from the recipient.
 * @return {signed} Boolean - True (1) is a valid signed message.
 */

function verify_signature(pubkey, privkey, passphrase, signed_message) {
    var openpgp = window.openpgp;
    var privKeys = openpgp.key.readArmored(privkey);
    var publicKeys = openpgp.key.readArmored(pubkey);
    var privKey = privKeys.keys[0];
    var success = privKey.decrypt(passphrase);
    var message = openpgp.cleartext.readArmored(signed_message);
    var verified = openpgp.verifyClearSignedMessage(publicKeys.keys, message);
    if (verified.signatures[0].valid === true) {
        return '1';
    } else {
        return '0';
    }
}
```


#### Public Key Length
```javascript
/**
 * Determines public key size (1024, 2048...)
 * @param  {data} String - Your recipient's Encrypted ASCII Armored public key.
 * @return {size} Integer - Length of the public key.
 */

function get_publickey_length(data) {
    var publicKey = openpgp.key.readArmored(data);
    var publicKeyPacket = publicKey.keys[0].primaryKey;
    if (publicKeyPacket !== null) {
        strength = getBitLength(publicKeyPacket);
    }

    function getBitLength(publicKeyPacket) {
        var size = -1;
        if (publicKeyPacket.mpi.length > 0) {
            size = (publicKeyPacket.mpi[0].byteLength() * 8);
        }
        return size;
    }
}
```


####HTML5 Storage
```javascript
HTML5 supports offline storage in the browser.
One possible use is key storage. For non-IE storage, use this format:

localStorage.setItem("companyname.privkey", privkey); 
localStorage.setItem("companyname.pubkey", key.publicKeyArmored);

localStorage.getItem("companyname.privkey"); 
localStorage.getItem("companyname.pubkey");
```



