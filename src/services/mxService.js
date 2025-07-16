// src/services/mxService.js
import { Resolver } from 'dns/promises'

// DNS resolver (Google + Cloudflare)
const resolver = new Resolver()
resolver.setServers(['8.8.8.8', '1.1.1.1'])

// MX Analysis
export async function analyzeMX (domain) {
  try {
    const mxRecords = await resolver.resolveMx(domain)

    if (!mxRecords || mxRecords.length === 0) {
      return {
        success: false,
        error: 'No MX records found',
        domain,
        recommendations: [
          'Add MX records to enable email delivery to your domain',
          'MX records specify which mail servers handle email for your domain',
          'Ensure proper priority values for load balancing and redundancy'
        ]
      }
    }

    // Sort by priority (lower numbers = higher priority)
    const sortedMx = mxRecords.sort((a, b) => a.priority - b.priority)

    const analysis = analyzeMXRecords(sortedMx)

    return {
      success: true,
      domain,
      records: sortedMx,
      ...analysis
    }
  } catch (error) {
    return {
      success: false,
      error: error.message,
      domain
    }
  }
}

function analyzeMXRecords (records) {
  const score = { base: 0, details: [] }
  const warnings = []
  const recommendations = []

  if (records.length === 0) {
    warnings.push('No MX records found')
    return { score: { value: 0, outOf: 3, level: 'Poor' }, warnings, recommendations }
  }

  score.base += 1
  score.details.push('MX records present (+1 point)')

  if (records.length >= 2) {
    score.base += 1
    score.details.push('Multiple MX records for redundancy (+1 point)')
  } else {
    recommendations.push('Consider adding backup MX records for redundancy')
  }

  // Check for proper priority configuration
  const priorities = records.map(r => r.priority)
  const uniquePriorities = [...new Set(priorities)]

  if (uniquePriorities.length === records.length) {
    score.base += 1
    score.details.push('Proper priority configuration (+1 point)')
  } else {
    warnings.push('Some MX records have the same priority')
    recommendations.push('Use unique priority values for better load balancing')
  }

  // Check for common mail provider patterns
  const exchanges = records.map(r => r.exchange.toLowerCase())
  const commonProviders = {
    'google.com': exchanges.some(ex => ex.includes('google.com') || ex.includes('gmail.com')),
    'microsoft.com': exchanges.some(ex => ex.includes('outlook.com') || ex.includes('hotmail.com') || ex.includes('live.com')),
    'cloudflare.com': exchanges.some(ex => ex.includes('cloudflare')),
    'protonmail.com': exchanges.some(ex => ex.includes('protonmail')),
    'zoho.com': exchanges.some(ex => ex.includes('zoho'))
  }

  const detectedProviders = Object.entries(commonProviders)
    .filter(([provider, detected]) => detected)
    .map(([provider]) => provider)

  if (detectedProviders.length > 0) {
    score.details.push(`Detected providers: ${detectedProviders.join(', ')}`)
  }

  // Check for potential issues
  const hasLowPriority = records.some(r => r.priority === 0)
  if (hasLowPriority) {
    warnings.push('Priority 0 detected - ensure this is intentional')
  }

  const hasHighPriority = records.some(r => r.priority > 50)
  if (hasHighPriority) {
    recommendations.push('Consider using lower priority values (closer to 0) for better delivery')
  }

  // Check for null MX record (RFC 7505)
  const hasNullMx = records.some(r => r.exchange === '.' || r.exchange === '')
  if (hasNullMx && records.length === 1) {
    warnings.push('Null MX record detected - this domain does not accept email')
    score.base = 0
    score.details = ['Null MX record - domain explicitly rejects email']
  } else if (hasNullMx) {
    warnings.push('Mixed null and regular MX records - this configuration may cause issues')
  }

  const finalScore = Math.max(Math.min(score.base, 3), 0)
  let securityLevel = 'Poor'
  if (finalScore >= 2.5) securityLevel = 'Excellent'
  else if (finalScore >= 2) securityLevel = 'Good'
  else if (finalScore >= 1) securityLevel = 'Fair'

  return {
    warnings,
    recommendations,
    score: {
      value: Math.round(finalScore * 10) / 10,
      outOf: 3,
      level: securityLevel,
      details: score.details
    }
  }
}
