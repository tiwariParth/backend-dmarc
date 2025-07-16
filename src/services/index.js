// src/services/index.js
// Central export file for all email authentication services

export { analyzeDMARC } from './dmarcService.js'
export { analyzeSPF } from './spfService.js'
export { analyzeDKIM } from './dkimService.js'
export { analyzeMX } from './mxService.js'
export { analyzeEmailSecurity } from './emailSecurityService.js'
