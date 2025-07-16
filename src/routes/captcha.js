import captcha from '../utils/captcha.js'

// Get captcha secrets from environment
const getCaptchaSecrets = () => {
  const secrets = []
  if (process.env.CAPTCHA_SECRET_1) secrets.push(process.env.CAPTCHA_SECRET_1)
  if (process.env.CAPTCHA_SECRET_2) secrets.push(process.env.CAPTCHA_SECRET_2)

  // Fallback secrets for development (should not be used in production)
  if (secrets.length === 0) {
    console.warn('WARNING: No CAPTCHA_SECRET environment variables found. Using default secrets for development only.')
    secrets.push('default-dev-secret-1', 'default-dev-secret-2')
  }

  return secrets
}

export default function (apiServer) {
  // Generate captcha endpoint
  apiServer.get('/v1/captcha/generate', async (req) => {
    try {
      const secrets = getCaptchaSecrets()
      const captchaData = captcha.generate(secrets, 300) // 5 minutes expiry

      return {
        status: 200,
        result: {
          success: true,
          captcha: {
            image: captchaData.data, // SVG image data
            probe: captchaData.probe // JWT token for verification
          }
        }
      }
    } catch (error) {
      return {
        status: 500,
        result: {
          success: false,
          error: 'Failed to generate captcha'
        }
      }
    }
  })

  // Verify captcha endpoint
  apiServer.post('/v1/captcha/verify', async (req) => {
    try {
      const { text, probe } = req.body

      if (!text || !probe) {
        return {
          status: 400,
          result: {
            success: false,
            error: 'Captcha text and probe are required'
          }
        }
      }

      const secrets = getCaptchaSecrets()
      const isValid = captcha.validate(secrets, { text, probe })

      if (isValid) {
        return {
          status: 200,
          result: {
            success: true,
            valid: true,
            message: 'Captcha verified successfully'
          }
        }
      } else {
        return {
          status: 400,
          result: {
            success: false,
            valid: false,
            error: 'Invalid captcha'
          }
        }
      }
    } catch (error) {
      return {
        status: 500,
        result: {
          success: false,
          error: 'Failed to verify captcha'
        }
      }
    }
  })
}
