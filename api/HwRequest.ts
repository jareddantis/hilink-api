/**
 * HwRequest.ts: Huawei HiLink API request builder
 *
 * @author jareddantis
 * @copyright MIT
 */

import axios from 'axios'

class HwRequest {
    private xmlStr: string
    private uri: string
    private headers: object

    constructor(uri: string, headers: object) {
        this.xmlStr = '<?xml version="1.0" encoding="utf-8"?><request>'
        this.uri = uri
        this.headers = headers
    }

    public add(node: string, content: string): void {
        let openTag = '<' + node + '>'
        let closeTag = '</' + node + '>'
        this.xmlStr += openTag + content + closeTag
    }

    public async send(): Promise<object> {
        let body: string = this.xmlStr + '</request>'
        return axios.post(this.uri, body, {
            headers: this.headers,
            responseType: 'text',
        })
    }
}

export = HwRequest
