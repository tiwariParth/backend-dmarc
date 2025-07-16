const rateLimitStore = new Map()

// Rate limiting utility function for express-async-api
export function checkRateLimit (req) {
  const ip = req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || 'unknown'
  const now = Date.now()
  const limit = 10 // requests per minute
  const window = 60 * 1000 // 1 minute

  if (!rateLimitStore.has(ip)) {
    rateLimitStore.set(ip, { count: 1, resetTime: now + window })
    return { allowed: true, remaining: limit - 1 }
  }

  const userData = rateLimitStore.get(ip)
  if (now > userData.resetTime) {
    userData.count = 1
    userData.resetTime = now + window
    return { allowed: true, remaining: limit - 1 }
  }

  if (userData.count >= limit) {
    return {
      allowed: false,
      error: 'Too many requests. Please try again later.',
      resetTime: userData.resetTime
    }
  }

  userData.count++
  return { allowed: true, remaining: limit - userData.count }
}

// Clean up old entries periodically
setInterval(() => {
  const now = Date.now()
  for (const [ip, userData] of rateLimitStore.entries()) {
    if (now > userData.resetTime) {
      rateLimitStore.delete(ip)
    }
  }
}, 5 * 60 * 1000) // Clean up every 5 minutes
