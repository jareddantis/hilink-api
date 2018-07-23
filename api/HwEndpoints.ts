/**
 * HwEndpoints.ts: Huawei HiLink web API endpoints
 *
 * @author jareddantis
 * @copyright MIT
 */

enum HwEndpoints {
    // Auth/login endpoints
    TOKEN = '/api/webserver/token',
    SCRAM_PHASE_ONE = '/api/user/challenge_login',
    SCRAM_PHASE_TWO = '/api/user/authentication_login',

    // Router control endpoints
    REBOOT = '/api/device/control',
}

export = HwEndpoints
