// src/services/dkimService.js
import { Resolver } from 'dns/promises'
import { dkimVerify } from 'mailauth/lib/dkim/verify.js'

// DNS resolver (Google + Cloudflare)
const resolver = new Resolver()
resolver.setServers(['8.8.8.8', '1.1.1.1'])

// Custom DNS resolver function for mailauth
const customResolver = async (domain, type) => {
  try {
    return await resolver.resolve(domain, type)
  } catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return []
    }
    throw error
  }
}

// DKIM Analysis
export async function analyzeDKIM (domain, selector = 'default') {
  try {
    const dkimRecord = `${selector}._domainkey.${domain}`

    try {
      const txtRecords = await resolver.resolveTxt(dkimRecord)
      const flatRecords = txtRecords.map(entry => entry.join(''))
      const dkimKey = flatRecords.find(txt => txt.includes('v=DKIM1') || txt.includes('k=rsa') || txt.includes('p='))

      if (!dkimKey) {
        return {
          success: false,
          error: `DKIM record not found for selector '${selector}'`,
          domain,
          selector,
          checkedRecord: dkimRecord,
          recommendations: [
            'Set up DKIM signing for your domain',
            'Common selectors to try: default, google, mail, dkim, selector1, selector2',
            'Contact your email provider for DKIM setup instructions'
          ]
        }
      }

      // Use mailauth for DKIM verification with a proper test message
      let mailauthResult = null
      try {
        // Create a proper DKIM-signed test message
        const testMessage = `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=${domain}; s=${selector}; h=from:to:subject; bh=dGVzdA==; b=test\r\nFrom: test@${domain}\r\nTo: test@example.com\r\nSubject: DKIM Test\r\n\r\nTest message for DKIM analysis`
        mailauthResult = await dkimVerify(testMessage, {
          resolver: customResolver
        })
      } catch (authError) {
        console.log('Mailauth DKIM error:', authError.message)
      }

      const analysis = analyzeDKIMRecord(dkimKey, mailauthResult)

      return {
        success: true,
        domain,
        selector,
        checkedRecord: dkimRecord,
        rawRecord: dkimKey,
        mailauthResult,
        ...analysis
      }
    } catch (dnsError) {
      return {
        success: false,
        error: `DKIM record not found for selector '${selector}'`,
        domain,
        selector,
        checkedRecord: dkimRecord,
        recommendations: [
          'Set up DKIM signing for your domain',
          'Common selectors to try: default, google, mail, dkim, selector1, selector2',
          'Contact your email provider for DKIM setup instructions'
        ]
      }
    }
  } catch (error) {
    return {
      success: false,
      error: `Failed to analyze DKIM for ${domain}: ${error.message}`,
      domain,
      selector
    }
  }
}

function analyzeDKIMRecord (record, dkimResult = null) {
  const score = { base: 0, details: [] }
  const warnings = []
  const recommendations = []

  // Basic DKIM validation
  if (!record.includes('v=DKIM1') && !record.includes('k=rsa') && !record.includes('p=')) {
    warnings.push('Invalid DKIM record format')
    return { score: { value: 0, outOf: 5, level: 'Poor' }, warnings, recommendations }
  }

  score.base += 1
  score.details.push('Valid DKIM record found (+1 point)')

  // Check for public key
  if (record.includes('p=') && !record.includes('p=;')) {
    score.base += 2
    score.details.push('Public key present (+2 points)')
  } else {
    warnings.push('No public key found in DKIM record')
  }

  // Check key type
  if (record.includes('k=rsa')) {
    score.base += 1
    score.details.push('RSA key type (+1 point)')
  } else if (record.includes('k=ed25519')) {
    score.base += 1.5
    score.details.push('Ed25519 key type - excellent security (+1.5 points)')
  }

  // Check hash algorithm
  if (record.includes('h=sha256')) {
    score.base += 1
    score.details.push('SHA-256 hash algorithm (+1 point)')
  } else if (record.includes('h=sha1')) {
    score.base += 0.5
    score.details.push('SHA-1 hash algorithm (+0.5 points)')
    recommendations.push('Consider upgrading to SHA-256 for better security')
  }

  // Check for service type restrictions
  if (record.includes('s=email')) {
    score.base += 0.5
    score.details.push('Restricted to email service (+0.5 points)')
  }

  // Check for flags
  if (record.includes('t=y')) {
    warnings.push('Testing mode enabled (t=y). Remove this flag for production.')
  }

  if (record.includes('t=s')) {
    warnings.push('Strict mode enabled. This may cause issues with some email systems.')
  }

  // Analyze key length (rough estimation from public key)
  const publicKeyMatch = record.match(/p=([A-Za-z0-9+/=]+)/)
  if (publicKeyMatch) {
    const keyLength = publicKeyMatch[1].length
    if (keyLength > 300) {
      score.base += 0.5
      score.details.push('Strong key length (+0.5 points)')
    } else if (keyLength < 200) {
      warnings.push('Potentially weak key length detected')
      recommendations.push('Consider using a stronger RSA key (2048+ bits)')
    }
  }

  // Add mailauth DKIM result if available
  if (dkimResult) {
    if (dkimResult.results && dkimResult.results.length > 0) {
      const result = dkimResult.results[0]
      if (result.status && result.status.result) {
        score.details.push(`Mailauth DKIM check: ${result.status.result}`)

        // Bonus points for successful verification
        if (result.status.result === 'pass') {
          score.base += 0.5
          score.details.push('DKIM verification passed (+0.5 points)')
        } else if (result.status.result === 'neutral') {
          score.details.push('DKIM verification neutral (no penalty)')
        }
      }

      if (result.info) {
        score.details.push(`DKIM info: ${result.info}`)
      }
    }
  }

  const finalScore = Math.max(Math.min(score.base, 5), 0)
  let securityLevel = 'Poor'
  if (finalScore >= 4) securityLevel = 'Excellent'
  else if (finalScore >= 3) securityLevel = 'Good'
  else if (finalScore >= 2) securityLevel = 'Fair'

  return {
    warnings,
    recommendations,
    score: {
      value: Math.round(finalScore * 10) / 10,
      outOf: 5,
      level: securityLevel,
      details: score.details
    }
  }
}
