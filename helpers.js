
const {
  CRLF,
  getTag,
  getDigest
} = require('./utils')

/**
 * Package a name and URI into an object.
 * @param {string} name The contact's name
 * @param {string} uri A SIP URI, for instance 'sip:user@domain:port'
 * @returns {{name: string, uri: string}}
 */
const makeContact = (name, uri) => ({
  name,
  uri
})

/**
 * Produce a JSON represention of a SIP Via header
 * See {@link https://tools.ietf.org/html/rfc3261#section-8.1.1.7 rfc3261} for details.
 * @param {string} host Hostname of the recipient SIP agent
 * @param {string} port Port of the recipient SIP agent
 * @returns {{version: string, potocol: string, host: string, port: string, rport:null, params:{ branch: string }}}
 */
const makeViaHeader = (host, port) =>[ {
  version: '2.0',
  protocol: 'UDP',
  host,
  port,
  rport: null,
  params: { //the 7 first characters are required by the SIP specification
    branch: `z9hG4bK${new Date().getTime()}_i4h`
  }
}]

/**
 * Augment the given headers dictionary with an Authorization header.
 * See {@link https://tools.ietf.org/html/rfc3261#section-20.7 rfc3261} for details.
 * @param {*} request The request being answered
 * @param {{username: string, password: string}} credentials
 * @param {*} authParams Content of the 'www-authenticate' header from the request to authenticate
 * @returns {Object} The headers from the request object given as parameter, augmented with the authentication credentials under the 'authorization' header
 */
const authenticateHeaders = (request, credentials, authParams) => {
  const authData = getDigest( credentials, authParams, request.method, request.uri )
  //quote the values
  Object.keys(authData)
    .filter( (k) => !['qop','nc'].includes(k) )
    .forEach( (k) => authData[k] = `"${authData[k]}"` )
  const authorization = Object.assign(authParams, authData)
  if( authorization.qop ){
    authorization.qop = authorization.qop.replace(/"/g,'')
  }
  return Object.assign({}, request.headers, {authorization: [authorization] } )
}

/**
 * Generate a Call-Id
 * See {@link https://tools.ietf.org/html/rfc3261#section-8.1.1.4 rfc3261} for details.
 * @returns {string} A Call-Id
 */
const makeCallId = () => `${new Date().getTime()}@i4h.test`

/**
 * Create a JSON representation of a REGISTER request
 * See {@link https://tools.ietf.org/html/rfc3261#section-10.2 rfc3261} for details.
 * @param {string} destinationURI SIP URI of the destination User Agent
 * @param {string} host Hostname of the recipient SIP agent
 * @param {string} port Port of the recipient SIP agent
 * @param {{name: string, uri: string}} contact
 * @param {string} userAgent
 * @param {Number} seq Sequence number for this request
 * @param {Number} expires Relative time after which the message expires, in seconds
 * @returns {*} REGISTER request
 */
const REGISTER = (destinationURI, host, port, contact, userAgent, seq, expires = 300) => ({
  method: 'REGISTER',
  uri: destinationURI,
  headers:{
    via: makeViaHeader( host, port ),
    'max-Forwards': 70,
    from: Object.assign( {}, contact, {params: {tag: getTag()}} ),
    to: Object.assign( {}, contact ),
    'call-id': makeCallId(),
    cseq: {seq, method:'REGISTER'},
    'user-agent': userAgent,
    contact: [contact],
    expires,
    allow: 'PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS',
    'content-length': 0
  }
})

/**
 * Create a JSON representation of an INVITE request
 * See {@link https://tools.ietf.org/html/rfc3261#section-13.2.1 rfc3261} for details.
 * @param {string} destinationURI SIP URI of the destination User Agent
 * @param {string} host Hostname of the recipient SIP agent
 * @param {string} port Port of the recipient SIP agent
 * @param {{name: string, uri: string}} contact
 * @param {string} userAgent
 * @param {Number} seq Sequence number for this request
 * @param {string} fromTag Tag for the From header field
 * @param {string} sdpPayload SDP content
 * @returns {*} INVITE request
 */
const INVITE = (destinationURI, host, port, contact, userAgent, seq, fromTag, sdpPayload) => ({
  method: 'INVITE',
  uri: destinationURI,
  headers:{
    via: makeViaHeader( host, port ),
    from:  { uri: `sip:${host}:${port}`, params: {tag: fromTag} },
    to: { uri: destinationURI },
    'call-id': makeCallId(),
    cseq: {seq, method:'INVITE'},
    'user-agent': userAgent,
    allow: 'INVITE, ACK, PRACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS',
    supported: 'timer, 100rel',
    'content-type': 'application/sdp'
  },
  content: sdpPayload
})

/**
 * Create a JSON representation of a BYE request
 * See {@link https://tools.ietf.org/html/rfc3261#section-15.1 rfc3261} for details.
 * @param {string} destinationURI SIP URI of the destination User Agent
 * @param {string} host Hostname of the recipient SIP agent
 * @param {string} port Port of the recipient SIP agent
 * @param {{name: string, uri: string}} contact
 * @param {string} userAgent
 * @param {Number} seq Sequence number for this request
 * @param {string} callId Call-Id of the session to terminate
 * @param {string} fromTag Tag for the From header field
 * @param {string} toTag Tag for the To header field
 * @returns {*} INVITE request
 */
const BYE = (destinationURI, host, port, contact, userAgent, seq, callId, fromTag, toTag) => ({
  method: 'BYE',
  uri: destinationURI,
  headers:{
    via: makeViaHeader( host, port ),
    from: Object.assign( {}, contact, { params: {tag: fromTag} } ),
    to: Object.assign( {}, contact, { params: {tag: toTag } } ),
    'call-id': callId,
    cseq: {seq, method:'BYE'},
    'user-agent': userAgent,
    'reason': 'Q.850 ;cause=16 ; text="Normal call clearing"',
    'content-length': 0
  }
})


/**
 * Generate a sess-id and sess-version for an SDP "o=" field
 * See {@link  https://tools.ietf.org/html/rfc4566#section-5.2 rfc4566} for dtetails
 * @returns {{id: Number, version: Number}}
 */
const createSessionIdAndVersion = () => ({
  id: new Date().getTime(),
  version: new Date().getTime()
})

/**
 * Return the remote address, remote port and SDP offer to
 * complete media negociation.
 * @param {string} localAddress IP address the User Agent will bind its UDP server to
 * @param {Number} localPort Port number the UDP server of the User Agen will listen to
 * @param {{o,m}} originAndMedia "o=" and "m=" fields from the SDP offer
 * @returns {{remoteAddress: string, remotePort: string, sdpAnswer: string }}
 */
const mediaNegociation = (localAddress, localPort, {o,m}) => {
  const remoteAddress = o.address
  const media = m
    .find(({media, fmt}) => media == 'audio' && fmt[0] == 0) //G.711 PCMU
  const remotePort = media.port

  const session = createSessionIdAndVersion()

  return {
    remoteAddress,
    remotePort,
    sdpAnswer:[
    'v=0',
    `o=- ${session.id} ${session.version} IN IP4 ${localAddress}`,
    's=I4H_BOT',
    `c=IN IP4 ${localAddress}`,
    't=0 0',
    `m=audio ${localPort} RTP/AVP 0`, //G.711 alaw
    'a=sendrecv',
    'a=rtpmap:0 PCMU/8000',
    'a=ptime:20',
    ''
    ].join(CRLF)
  }
}

module.exports = {
  makeContact,
  mediaNegociation,
  REGISTER,
  INVITE,
  BYE,
  authenticateHeaders,
  createSessionIdAndVersion
}

