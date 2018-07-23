/**
 * HwScramAuth.ts: Huawei HiLink SCRAM authentication
 *
 * @author jareddantis
 * @copyright MIT
 */

import * as CryptoJS from 'crypto-js'

class HwScramAuth {
    private readonly KEYSIZE = 8
    private clientNonce: string
    private iters: number
    private pwd: string
    private salt: string
    private serverNonce: string
    private sigSecret: string

    /**
     * Constructor for HwScramAuth object
     * @param {string} pwd Password to derive keys from using PBKDF2
     */
    constructor(pwd: string) {
        this.pwd = pwd
    }

    /**
     * Generates a random 32-char nonce
     * @return {string} Generated nonce
     */
    public generateNonce(): string {
        return CryptoJS.lib.WordArray.random(32).toString()
    }

    /**
     * Sets the SCRAM authentication parameters for proof calculation
     * and key derivation.
     * @param {string} cNonce Client nonce
     * @param {string} sNonce Server nonce
     * @param {string} salt   Server-provided PBKDF2 salt
     * @param {number} iters  Server-provided PBKDF2 iterations
     */
    public setParams(cNonce: string, sNonce: string, salt: string, iters: number) {
        this.clientNonce = cNonce
        this.iters = iters
        this.salt = salt
        this.serverNonce = sNonce
        this.sigSecret = cNonce + ',' + sNonce + ',' + sNonce
    }

    /**
     * Derives and hashes a SCRAM client key using PBKDF2 and SHA256
     * @param  {string} hmacKey Secret to use for HMAC
     * @return {any}            HMAC-SHA256 hashed key
     */
    public deriveKey(hmacKey: string): any {
        let saltedPwd = CryptoJS.PBKDF2(this.pwd, CryptoJS.enc.Hex.parse(this.salt), {
            hasher: CryptoJS.algo.SHA256,
            iterations: this.iters,
            keySize: this.KEYSIZE,
        })
        return CryptoJS.HmacSHA256(saltedPwd, hmacKey)
    }

    /**
     * Calculates client login proof
     * @return {string} Login proof
     */
    public calcProof(): string {
        let clientKey = this.deriveKey('Client Key')
        let clientDgst = clientKey.toString()
        let clientHasher = CryptoJS.algo.SHA256.create()
        let storedKey = clientHasher.update(clientKey).finalize()
        let signature = CryptoJS.HmacSHA256(storedKey, this.sigSecret)

        for (let i of [...Array(clientKey.sigBytes / 4).keys()]) {
            clientKey.words[i] = clientKey.words[i] ^ signature.words[i]
        }

        // Allow debug from node CLI
        if (typeof document === 'undefined') {
            console.log('')
            console.log('Client nonce:     ' + this.clientNonce)
            console.log('Server nonce:     ' + this.serverNonce)
            console.log('Salt:             ' + this.salt)
            console.log('----------------------------')
            console.log('Client digest:    ' + clientDgst)
            console.log('Stored digest:    ' + storedKey.toString())
            console.log('Signature digest: ' + signature.toString())
            console.log('----------------------------')
            console.log('Login proof:      ' + clientKey.toString())
            console.log('')
        }

        return clientKey.toString()
    }

    /**
     * Calculates server login proof
     * @return {string} [description]
     */
    public calcServerProof(): string {
        let serverKey = this.deriveKey('Server Key')
        let signature = CryptoJS.HmacSHA256(serverKey, this.sigSecret)
        return signature.toString()
    }

    /**
     * Calculates RSA public key signature
     * @param  {string} key Server-provided RSA public key
     * @return {string}     Calculated signature
     */
    public calcPubSig(key: string): string {
        let serverKeyD = this.deriveKey('Server Key')
        let serverKey = CryptoJS.enc.Hex.parse(serverKeyD.toString())
        let publicKey = CryptoJS.enc.Hex.parse(key)
        let signature = CryptoJS.HmacSHA256(publicKey, serverKey)
        return signature.toString()
    }

}

export = HwScramAuth
