import createApiServer from 'express-async-api'
import emailAuth from './emailAuth.js'
import captcha from './captcha.js'
import pino from 'pino'
import pinoHttp from 'pino-http'

const maxFileSize = process.env.MAX_FILE_SIZE
export default () => {
  function errorHandler (e) {
    /* c8 ignore next 9 */
    if (e.code === 'LIMIT_FILE_SIZE') {
      return {
        status: 413,
        error: {
          name: 'PAYLOAD_TOO_LARGE',
          message: 'File size limit exceeded. Maximum file size allowed is ' + (Number(maxFileSize) / (1024 * 1024)).toFixed(2) + 'mb'
        }
      }
    }
    return {
      status: e.status,
      error: {
        name: e.name,
        message: e.message
      }
    }
  }

  const logger = pino({ level: 'info' })
  const logFunction = (req, res) => {
    req.log = pinoHttp({ logger })(req, res)
  }

  const apiServer = createApiServer(errorHandler, logFunction, { limit: '50mb' })

  emailAuth(apiServer)
  captcha(apiServer)

  return apiServer
}
