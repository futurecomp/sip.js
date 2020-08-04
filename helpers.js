const {
  CRLF,
  getTag,
  getDigest
} = require('./utils')

const generateBranch = () => {
  //see https://tools.ietf.org/html/rfc3261#section-7.3
  return `z9hG4bK${new Date().getTime()}`
}

const makeContact = (name, uri) => ({
  name,
  uri
})

const makeViaHeader = (host, port, branch) =>[ {
  version: '2.0',
  protocol: 'UDP',
  host,
  port,
  rport: null,
  params: { branch }
}]


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

const getCallId = () => `${new Date().getTime()}@i4h.test`

const REGISTER = (destinationURI, host, port, contact, userAgent, seq, expires = 300) => ({
  method: 'REGISTER',
  uri: destinationURI,
  headers:{
    via: makeViaHeader( host, port, generateBranch() ),
    'max-Forwards': 70,
    from: Object.assign( {}, contact, {params: {tag: getTag()}} ),
    to: Object.assign( {}, contact ),
    'call-id': getCallId(),
    cseq: {seq, method:'REGISTER'},
    'user-agent': userAgent,
    contact: [contact],
    expires,
    allow: 'PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS',
    'content-length': 0
  }
})

const INVITE = (destinationURI, host, port, contact, userAgent, seq, fromTag, sdpPayload) => ({
  method: 'INVITE',
  uri: destinationURI,
  headers:{
    via: makeViaHeader( host, port, generateBranch() ),
    from:  { uri: `sip:${host}:${port}`, params: {tag: fromTag} },
    to: { uri: destinationURI },
    'call-id': getCallId(),
    cseq: {seq, method:'INVITE'},
    'user-agent': userAgent,
    allow: 'INVITE, ACK, PRACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS',
    supported: 'timer, 100rel',
    'content-type': 'application/sdp'
  },
  content: sdpPayload
})

const BYE = (destinationURI, host, port, contact, userAgent, seq, callId, fromTag, toTag) => ({
  method: 'BYE',
  uri: destinationURI,
  headers:{
    via: makeViaHeader( host, port, generateBranch() ),
    from: Object.assign( {}, contact, { params: {tag: fromTag} } ),
    to: Object.assign( {}, contact, { params: {tag: toTag } } ),
    'call-id': callId,
    cseq: {seq, method:'BYE'},
    'user-agent': userAgent,
    'reason': 'Q.850 ;cause=16 ; text="Normal call clearing"',
    'content-length': 0
  }
})


const createSessionIdAndVersion = () => ({
  id: new Date().getTime(),
  version: new Date().getTime()
})

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

