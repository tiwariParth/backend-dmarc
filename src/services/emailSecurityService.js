// src/services/emailSecurityService.js
import { analyzeDMARC } from './dmarcService.js'
import { analyzeSPF } from './spfService.js'
import { analyzeDKIM } from './dkimService.js'
import { analyzeMX } from './mxService.js'

// Comprehensive Email Security Check
export async function analyzeEmailSecurity (domain, dkimSelector = 'default') {
  const results = await Promise.allSettled([
    analyzeDMARC(domain),
    analyzeSPF(domain),
    analyzeDKIM(domain, dkimSelector),
    analyzeMX(domain)
  ])

  const [dmarcResult, spfResult, dkimResult, mxResult] = results.map(r =>
    r.status === 'fulfilled' ? r.value : { success: false, error: r.reason.message }
  )

  // Calculate overall security score
  let totalScore = 0
  let maxScore = 0

  if (dmarcResult.success && dmarcResult.score) {
    totalScore += dmarcResult.score.value
    maxScore += dmarcResult.score.outOf
  }

  if (spfResult.success && spfResult.score) {
    totalScore += spfResult.score.value
    maxScore += spfResult.score.outOf
  }

  if (dkimResult.success && dkimResult.score) {
    totalScore += dkimResult.score.value
    maxScore += dkimResult.score.outOf
  }

  if (mxResult.success && mxResult.score) {
    totalScore += mxResult.score.value
    maxScore += mxResult.score.outOf
  }

  const overallScore = maxScore > 0 ? (totalScore / maxScore) * 10 : 0
  let securityLevel = 'Poor'
  if (overallScore >= 8) securityLevel = 'Excellent'
  else if (overallScore >= 6) securityLevel = 'Good'
  else if (overallScore >= 4) securityLevel = 'Fair'

  // Generate comprehensive recommendations
  const allRecommendations = []
  const allWarnings = []

  if (dmarcResult.recommendations) allRecommendations.push(...dmarcResult.recommendations)
  if (spfResult.recommendations) allRecommendations.push(...spfResult.recommendations)
  if (dkimResult.recommendations) allRecommendations.push(...dkimResult.recommendations)
  if (mxResult.recommendations) allRecommendations.push(...mxResult.recommendations)

  if (dmarcResult.warnings) allWarnings.push(...dmarcResult.warnings)
  if (spfResult.warnings) allWarnings.push(...spfResult.warnings)
  if (dkimResult.warnings) allWarnings.push(...dkimResult.warnings)
  if (mxResult.warnings) allWarnings.push(...mxResult.warnings)

  // Priority recommendations based on security impact
  const priorityRecommendations = []

  if (!dmarcResult.success) {
    priorityRecommendations.push('🔴 CRITICAL: Set up DMARC policy to prevent email spoofing')
  } else if (dmarcResult.parsed?.p === 'none') {
    priorityRecommendations.push('🟡 IMPORTANT: Upgrade DMARC policy from "none" to "quarantine" or "reject"')
  }

  if (!spfResult.success) {
    priorityRecommendations.push('🔴 CRITICAL: Configure SPF record to authorize mail servers')
  }

  if (!dkimResult.success) {
    priorityRecommendations.push('🟡 IMPORTANT: Enable DKIM signing for email authentication')
  }

  if (!mxResult.success) {
    priorityRecommendations.push('🔴 CRITICAL: Configure MX records for email delivery')
  }

  return {
    domain,
    dmarc: dmarcResult,
    spf: spfResult,
    dkim: dkimResult,
    mx: mxResult,
    overallScore: {
      value: Math.round(overallScore * 10) / 10,
      outOf: 10,
      level: securityLevel
    },
    summary: {
      totalChecks: 4,
      passedChecks: [dmarcResult, spfResult, dkimResult, mxResult].filter(r => r.success).length,
      warnings: allWarnings,
      recommendations: allRecommendations,
      priorityRecommendations
    }
  }
}
