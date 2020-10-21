/**
 * Miscelleanous functions useful for working with SIP.
 * @module sip/utils
 */

const http = require('http')
const uuid = require('uuid')
const crypto = require('crypto')

/**
 * Produce a hexadecimal representation of the md5 hash
 * of the input string.
 * @param {string} s Input string
 * @returns {string} The md5 hash of the input string encoded in hexadecimal
 */
function md5(s) {
  return crypto.createHash('md5').update(s).digest('hex')
}

/**
 * Convert the input integer to hexadecimal and return only
 * the 8 rightmost symbols.
 * @param {number} num Input number in base 10
 * @return {string} 8 characters long string, padded with 0 is necessary, of the input number 8 rightmost symbols after convertion to hexadecimal
 */
function hex8(num)
{
  return ("00000000" + num.toString(16)).slice(-8);
}


/**
 * @constant
 * @type {string}
 * @default
 */
const CRLF = '\r\n'


/**
 * Obtain the host external IPv4 by querying ipv4bot.whatismyipaddress.com
 * @return {string} The host external IPv4 address as seen by ipv4bot.whatismyipaddress.com
 */
const getExternalIP = async ()=>{
  const options = {
    host: 'ipv4bot.whatismyipaddress.com',
    port: 80,
    path: '/'
  }

  const IP = new Promise((s,f) => {
    http.get(options, function(res) {
      res.on("data", function(chunk) {
        s( chunk.toString('utf-8') )
      })
    }).on('error', function(e) {
      f( e.message )
    })
  })

  return (await IP)
}

/**
 * Produce an UUID v4 suitable for a For or To header tag field.
 * @return {string} A randome UUID v4
 */
const getTag = () => uuid.v4()

/**
 * Request counter
 * @type {number}
 */
let _nc = 0

/**
 * Produce an authentication digest to be included in an Authorization header.
 * See {@link https://en.wikipedia.org/wiki/Digest_access_authentication Digest Access Authentication} for details.
 * @params {{username: string, password: string}} credentials
 * @param {{realm: string, nonce: string, qop: (string|undefined)}} auth_params Authorization parameters provided by the SIP peer
 * @param {string} method SIP method of the request for authorization
 * @param {string} requestURI URI of the SIP peer
 * @param {string} [cnonce] 8 character client nonce in hexadecimal. If not provided a random one will be generated.
 * @return {{uri: string, username: string, nc: number, cnonce: string, response: string}} All the authentication fields for the Authorization header
 */
const getDigest = ({username, password}, auth_params, method, requestURI, cnonce = crypto.pseudoRandomBytes(8).toString('hex') ) => {
  const realm = auth_params.realm.replace(/"/g,'')
  if (!realm) {
    throw new Error("Realm not found in www-authenticate header.")
  }

  const nonce = auth_params.nonce.replace(/"/g,'')
  if (!nonce) {
    throw new Error("Nonce not found in www-authenticate header.");
  }
  const ha1 = md5(username+':'+realm+':'+password)
  const ha2 = md5(method+':'+requestURI)


  const qop = auth_params.qop.replace(/"/g,'')
  if (!qop) {
    return {
      uri: requestURI,
      username,
      response: md5(ha1+':'+nonce+':'+ha2)
    }
    }

    if( qop != 'auth'){
      throw new Error(`Unsupported Quality Of Protection: '${qop}'.`)
    }

    const nc = hex8(++_nc)
    const response = md5(ha1+':'+nonce+':'+nc+':'+cnonce+':auth:'+ha2)
    return {
      uri: requestURI,
      username,
      nc,
      cnonce,
      response
    }
}

//TODO: move to a proper unit test
const testDigest = ()=>{
  const auth_params = {
    realm: "asterisk",
    nonce: "1585558405/882990811414b00b05f596211615f58c",
    opaque: "66706dec78339972",
    qop: "auth"
  }

  const credentials = {
    username: '+4915758093134',
    password: 'pHZD3uHt%tw$DV7L'
  }

  const cnonce = "L-Q3J80qGDu3n-ZZx1I.8nqvRsJvbIlg"

  const digest = getDigest(credentials, auth_params, "REGISTER", "sip:i4hearth.hopto.org:5061", cnonce )

  const expectedResponse = "08937ec91dfed2d6a1c969269990cd38"
  console.log( digest.response, expectedResponse, digest.response == expectedResponse )
}


module.exports = {
  CRLF,
  getExternalIP,
  getTag,
  getDigest
}
