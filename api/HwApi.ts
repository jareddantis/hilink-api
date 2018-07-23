/**
 * HwApi.ts: Huawei HiLink API
 *
 * @author jareddantis
 * @copyright MIT
 */

import axios, { AxiosResponse } from 'axios'
import { parseString as parseXmlStr } from 'xml2js'
import HwEndpoints = require('./HwEndpoints')
import HwRequest = require('./HwRequest')
import HwScramAuth = require('./HwScramAuth')

class HwApi {
    private readonly DEFAULT_GETOPTS: object = {
        method: 'get',
        responseType: 'text',
    }
    private authPwd: string
    private authUser: string
    private server: string
    private sessionId: string

    /**
     * Constructor for HwApi
     * @param {string} server Router IP address
     * @param {string} user   Admin username
     * @param {string} pwd    Admin password
     */
    constructor(server: string, user: string, pwd: string) {
        this.server = 'http://' + server
        this.authUser = user
        this.authPwd = pwd
    }

    /**
     * Performs login to router using SCRAM authentication
     * @return {string} Final verification token
     */
    public login(): string {
        let scram = new HwScramAuth(this.authPwd)
        let clientNonce: string = scram.generateNonce()
        let serverNonce: string
        let veriToken: string

        // Setup session
        this.initSession().then((ok) => {
            if (ok) {
                // Request server token
                return this.getServerToken()
            }
            throw new Error('Session failed to initialize')
        // SCRAM auth phase one
        }).then((token) => {
            // Send first SCRAM auth POST
            let uri = this.server + HwEndpoints.SCRAM_PHASE_ONE
            let scramOne = new HwRequest(uri, {
                'Content-Type': 'text/html',
                '__RequestVerificationToken': token[0].substring(32),
            })
            scramOne.add('username', this.authUser)
            scramOne.add('firstnonce', clientNonce)
            scramOne.add('mode', '1')
            return scramOne.send()
        // SCRAM auth phase two
        }).then((scramReply: AxiosResponse) => {
            veriToken = scramReply.headers['__requestverificationtoken']
            if (veriToken == null) {
                throw new Error('Server did not supply verification token')
            }
            return scramReply.data
        }).then((responseStr: string) => {
            return new Promise((res, rej) => {
                parseXmlStr(responseStr, (err, result) => {
                    if (result.error != null) {
                        let waitTime = result.error.waittime
                        rej(new Error('Too many incorrect login attempts, try again in ' + waitTime + ' minutes.'))
                    } else if (err != null) {
                        rej(err)
                    }

                    // Save SCRAM parameters for later use
                    serverNonce = result.response.servernonce[0]
                    let salt = result.response.salt[0]
                    let iterations = parseInt(result.response.iterations[0], 10)
                    try {
                        scram.setParams(clientNonce, serverNonce, salt, iterations)
                        res(scram.calcProof())
                    } catch (e) {
                        throw new Error('Failed to generate client proof. ' + e)
                    }
                })
            })
        }).then((loginProof: string) => {
            // Send final SCRAM auth POST
            let uri = this.server + HwEndpoints.SCRAM_PHASE_TWO
            let scramTwo = new HwRequest(uri, {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                '__RequestVerificationToken': veriToken,
            })
            scramTwo.add('clientproof', loginProof)
            scramTwo.add('finalnonce', serverNonce)
            return scramTwo.send()
        }).then((scramReply: AxiosResponse) => {
            // Save final token
            if (scramReply.headers['__requestverificationtokenone'] != null) {
                veriToken = scramReply.headers['__requestverificationtokenone']
                console.log('Logged in successfully: ' + veriToken)
            } else if (veriToken == null) {
                throw new Error('Server did not supply new verification token')
            }

            return scramReply.data
        }).then((text) => {
            return new Promise((res, rej) => {
                parseXmlStr(text, (err, result) => {
                    if (err != null) {
                        rej(new Error('SCRAM auth failed. ' + err))
                    }

                    // Verify server response
                    try {
                        let calcProof = scram.calcServerProof()
                        let resProof = result.response.serversignature[0]

                        if (calcProof === resProof) {
                            // Server is legitimate, check RSA public key
                            let serverSig = result.response.rsapubkeysignature[0]
                            let pubKey = result.response.rsan[0]
                            let pubKeySig = scram.calcPubSig(pubKey)

                            if (serverSig === pubKeySig) {
                                // Server's RSA public key is valid, save RSA public key
                                let lS = window.localStorage
                                let rsaN = result.response.rsan[0]
                                let rsaE = result.response.rsae[0]
                                lS.setItem("rsan", rsaN)
                                lS.setItem("rsae", rsaE)

                                if (typeof document !== 'undefined') {
                                    let rsaData = 'rsan=' + rsaN + ', rsae=' + rsaE
                                    document.querySelector('h2').innerText = 'Logged in!'
                                    document.querySelector('code').innerText = rsaData
                                } else {
                                    console.log('Server identity successfully verified.')
                                }
                            } else {
                                rej(new Error('Server provided an invalid RSA public key.'))
                            }
                        } else {
                            rej(new Error('Could not verify server identity.'))
                        }
                    } catch (e) {
                        rej(new Error('Failed to generate server proof. ' + e))
                    }
                })
            })
        }).catch((error) => {
            let errHead = 'Error while logging in'
            let errMsg = error.message

            if (typeof document !== 'undefined') {
                document.querySelector('h2').innerText = errHead
                document.querySelector('code').innerText = errMsg
            } else {
                console.error(errHead + ': ' + errMsg)
            }
        })

        return veriToken
    }

    /**
     * Initializes session by requesting session ID from router
     * @return {Promise<boolean>} Promise for server response
     */
    private async initSession(): Promise<boolean> {
        let retVal = false

        await axios.get(this.server, this.DEFAULT_GETOPTS)
            .then((response: AxiosResponse) => {
                // Since we can't read cookies from XHR responses,
                // we assume that the request was successful and
                // the SessionID cookie was set.
                retVal = response.statusText === 'OK'
            })

        return retVal
    }

    /**
     * Requests authentication token from router
     * @return {Promise<string>} Promise for token
     */
    private async getServerToken(): Promise<string> {
        let uri = this.server + HwEndpoints.TOKEN
        let token: string

        await axios.get(uri, this.DEFAULT_GETOPTS)
            .then((response: AxiosResponse) => {
                parseXmlStr(response.data, (err, result) => {
                    token = result.response.token
                })
            })

        return token
    }

}

export = HwApi
