const { requests, lookup } = require('../../protocol/requests')
const apiKeys = require('../../protocol/requests/apiKeys')
const plainAuthenticatorProvider = require('./plain')
const SCRAM256Authenticator = require('./scram256')
const SCRAM512Authenticator = require('./scram512')
const AWSIAMAuthenticator = require('./awsIam')
const OAuthBearerAuthenticator = require('./oauthBearer')
const { KafkaJSSASLAuthenticationError } = require('../../errors')

const BUILT_IN_AUTHENTICATORS = {
  PLAIN: plainAuthenticatorProvider,
}

const OLD_AUTHENTICATORS = {
  'SCRAM-SHA-256': SCRAM256Authenticator,
  'SCRAM-SHA-512': SCRAM512Authenticator,
  AWS: AWSIAMAuthenticator,
  OAUTHBEARER: OAuthBearerAuthenticator,
}

const OLD_SUPPORTED_MECHANISMS = Object.keys(OLD_AUTHENTICATORS)
const UNLIMITED_SESSION_LIFETIME = '0'

module.exports = class SASLAuthenticator {
  constructor(connection, logger, versions, supportAuthenticationProtocol) {
    this.connection = connection
    this.logger = logger
    this.sessionLifetime = UNLIMITED_SESSION_LIFETIME

    const lookupRequest = lookup(versions)
    this.saslHandshake = lookupRequest(apiKeys.SaslHandshake, requests.SaslHandshake)
    this.protocolAuthentication = supportAuthenticationProtocol
      ? lookupRequest(apiKeys.SaslAuthenticate, requests.SaslAuthenticate)
      : null
  }

  async authenticate() {
    const mechanism = this.connection.sasl.mechanism.toUpperCase()
    const handshake = await this.connection.send(this.saslHandshake({ mechanism }))
    if (!handshake.enabledMechanisms.includes(mechanism)) {
      throw new KafkaJSSASLAuthenticationError(
        `SASL ${mechanism} mechanism is not supported by the server`
      )
    }

    const saslAuthenticate = async ({ request, response, authExpectResponse }) => {
      if (this.protocolAuthentication) {
        const requestAuthBytes = await request.encode()
        const authResponse = await this.connection.send(
          this.protocolAuthentication({ authBytes: requestAuthBytes })
        )

        // `0` is a string because `sessionLifetimeMs` is an int64 encoded as string.
        // This is not present in SaslAuthenticateV0, so we default to `"0"`
        this.sessionLifetime = authResponse.sessionLifetimeMs || UNLIMITED_SESSION_LIFETIME

        if (!authExpectResponse) {
          return
        }

        const { authBytes: responseAuthBytes } = authResponse
        const payloadDecoded = await response.decode(responseAuthBytes)
        return response.parse(payloadDecoded)
      }

      return this.connection.sendAuthRequest({ request, response, authExpectResponse })
    }

    if (OLD_SUPPORTED_MECHANISMS.includes(mechanism)) {
      const Authenticator = OLD_AUTHENTICATORS[mechanism]
      await new Authenticator(this.connection, this.logger, saslAuthenticate).authenticate()
    } else {
      if (Object.keys(BUILT_IN_AUTHENTICATORS).includes(mechanism)) {
        this.connection.sasl.authenticationProvider = BUILT_IN_AUTHENTICATORS[mechanism](
          this.connection.sasl
        )
      }
      await this.connection.sasl
        .authenticationProvider(
          this.connection.host,
          this.connection.port,
          this.logger.namespace(`SaslAuthenticator-${mechanism}`),
          saslAuthenticate
        )
        .authenticate()
    }
  }
}
