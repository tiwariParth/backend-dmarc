import { analyzeDMARC, analyzeSPF, analyzeDKIM, analyzeMX, analyzeEmailSecurity } from '../services/index.js'
import { checkRateLimit } from '../utils/rateLimit.js'
import captcha from '../utils/captcha.js'

// Helper function to validate and clean domain
function validateDomain (domain) {
  if (!domain) {
    return { isValid: false, error: 'Domain is required' }
  }

  const cleanDomain = domain.trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0]

  if (!cleanDomain || cleanDomain.length === 0) {
    return { isValid: false, error: 'Please enter a valid domain name' }
  }

  return { isValid: true, domain: cleanDomain }
}

// Helper function to get captcha secrets
function getCaptchaSecrets () {
  const secrets = []
  if (process.env.CAPTCHA_SECRET_1) secrets.push(process.env.CAPTCHA_SECRET_1)
  if (process.env.CAPTCHA_SECRET_2) secrets.push(process.env.CAPTCHA_SECRET_2)

  // Fallback secrets for development
  if (secrets.length === 0) {
    secrets.push('default-dev-secret-1', 'default-dev-secret-2')
  }

  return secrets
}

// Helper function to validate captcha
function validateCaptcha (captchaText, captchaProbe) {
  if (!captchaText || !captchaProbe) {
    return { isValid: false, error: 'Captcha verification is required' }
  }

  const secrets = getCaptchaSecrets()
  const isValid = captcha.validate(secrets, { text: captchaText, probe: captchaProbe })

  if (!isValid) {
    return { isValid: false, error: 'Invalid captcha. Please try again.' }
  }

  return { isValid: true }
}

// Helper function to handle rate limiting
function handleRateLimit (req) {
  const rateLimitResult = checkRateLimit(req)
  if (!rateLimitResult.allowed) {
    return {
      status: 429,
      error: {
        message: rateLimitResult.error,
        resetTime: rateLimitResult.resetTime
      }
    }
  }
  return null
}

export default function (apiServer) {
  // DMARC Analysis Endpoint
  apiServer.post('/v1/analyze-dmarc', async (req) => {
    const rateLimitError = handleRateLimit(req)
    if (rateLimitError) return rateLimitError

    const { domain, captchaText, captchaProbe } = req.body

    // Validate captcha
    const captchaValidation = validateCaptcha(captchaText, captchaProbe)
    if (!captchaValidation.isValid) {
      return {
        status: 400,
        result: {
          success: false,
          error: captchaValidation.error
        }
      }
    }

    const validation = validateDomain(domain)

    if (!validation.isValid) {
      return {
        status: 400,
        result: {
          success: false,
          error: validation.error
        }
      }
    }

    const result = await analyzeDMARC(validation.domain)
    return {
      status: 200,
      result
    }
  })

  // SPF Analysis Endpoint
  apiServer.post('/v1/analyze-spf', async (req) => {
    const rateLimitError = handleRateLimit(req)
    if (rateLimitError) return rateLimitError

    const { domain, captchaText, captchaProbe } = req.body

    // Validate captcha
    const captchaValidation = validateCaptcha(captchaText, captchaProbe)
    if (!captchaValidation.isValid) {
      return {
        status: 400,
        result: {
          success: false,
          error: captchaValidation.error
        }
      }
    }

    const validation = validateDomain(domain)

    if (!validation.isValid) {
      return {
        status: 400,
        result: {
          success: false,
          error: validation.error
        }
      }
    }

    const result = await analyzeSPF(validation.domain)
    return {
      status: 200,
      result
    }
  })

  // DKIM Analysis Endpoint
  apiServer.post('/v1/analyze-dkim', async (req) => {
    const rateLimitError = handleRateLimit(req)
    if (rateLimitError) return rateLimitError

    const { domain, selector = 'default', captchaText, captchaProbe } = req.body

    // Validate captcha
    const captchaValidation = validateCaptcha(captchaText, captchaProbe)
    if (!captchaValidation.isValid) {
      return {
        status: 400,
        result: {
          success: false,
          error: captchaValidation.error
        }
      }
    }

    const validation = validateDomain(domain)

    if (!validation.isValid) {
      return {
        status: 400,
        result: {
          success: false,
          error: validation.error
        }
      }
    }

    const result = await analyzeDKIM(validation.domain, selector)
    return {
      status: 200,
      result
    }
  })

  // MX Analysis Endpoint
  apiServer.post('/v1/analyze-mx', async (req) => {
    const rateLimitError = handleRateLimit(req)
    if (rateLimitError) return rateLimitError

    const { domain, captchaText, captchaProbe } = req.body

    // Validate captcha
    const captchaValidation = validateCaptcha(captchaText, captchaProbe)
    if (!captchaValidation.isValid) {
      return {
        status: 400,
        result: {
          success: false,
          error: captchaValidation.error
        }
      }
    }

    const validation = validateDomain(domain)

    if (!validation.isValid) {
      return {
        status: 400,
        result: {
          success: false,
          error: validation.error
        }
      }
    }

    const result = await analyzeMX(validation.domain)
    return {
      status: 200,
      result
    }
  })

  // Comprehensive Email Security Analysis Endpoint
  apiServer.post('/v1/analyze-email-security', async (req) => {
    const rateLimitError = handleRateLimit(req)
    if (rateLimitError) return rateLimitError

    const { domain, dkimSelector = 'default', captchaText, captchaProbe } = req.body

    // Validate captcha
    const captchaValidation = validateCaptcha(captchaText, captchaProbe)
    if (!captchaValidation.isValid) {
      return {
        status: 400,
        result: {
          success: false,
          error: captchaValidation.error
        }
      }
    }

    const validation = validateDomain(domain)

    if (!validation.isValid) {
      return {
        status: 400,
        result: {
          success: false,
          error: validation.error
        }
      }
    }

    const result = await analyzeEmailSecurity(validation.domain, dkimSelector)
    return {
      status: 200,
      result
    }
  })

  // Legacy DMARC endpoint for backward compatibility
  apiServer.post('/v1/analyze-dmarc-by-domain', async (req) => {
    const rateLimitError = handleRateLimit(req)
    if (rateLimitError) return rateLimitError

    const { domain, captchaText, captchaProbe } = req.body

    // Validate captcha
    const captchaValidation = validateCaptcha(captchaText, captchaProbe)
    if (!captchaValidation.isValid) {
      return {
        status: 400,
        result: {
          success: false,
          error: captchaValidation.error
        }
      }
    }

    const validation = validateDomain(domain)

    if (!validation.isValid) {
      return {
        status: 400,
        result: {
          success: false,
          error: validation.error
        }
      }
    }

    const result = await analyzeDMARC(validation.domain)
    return {
      status: 200,
      result
    }
  })
}
