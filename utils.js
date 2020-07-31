const http = require('http')
const uuid = require('uuid')

const crypto = require('crypto')

const CRLF = '\r\n'

function md5(s) {
  return crypto.createHash('md5').update(s).digest('hex');
}

function hex8(num)
{
  return ("00000000" + num.toString(16)).slice(-8);
}

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

const getTag = () => uuid.v4()

//nonce count
let _nc = 0

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
  getDigest,
  testDigest,
}
