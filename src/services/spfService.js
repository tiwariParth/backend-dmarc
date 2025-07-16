// src/services/spfService.js
import { Resolver } from "dns/promises";
import { createRequire } from "module";

// Import mailauth using CommonJS require since it's a CommonJS module
const require = createRequire(import.meta.url);
const { spf } = require("mailauth/lib/spf");

// DNS resolver (Google + Cloudflare)
const resolver = new Resolver();
resolver.setServers(["8.8.8.8", "1.1.1.1"]);

// Custom DNS resolver function for mailauth
const customResolver = async (domain, type) => {
  try {
    return await resolver.resolve(domain, type);
  } catch (error) {
    if (error.code === "ENOTFOUND" || error.code === "ENODATA") {
      return [];
    }
    throw error;
  }
};

/**
 * Main function to analyze a domain's SPF record using mailauth
 */
export async function analyzeSPF(domain) {
  try {
    // First, let's get the raw SPF record
    let txtRecords;
    try {
      txtRecords = await resolver.resolveTxt(domain);
    } catch (error) {
      if (error.code === "ENODATA" || error.code === "ENOTFOUND") {
        return {
          success: false,
          error: "No SPF record found.",
          domain,
          recommendations: [
            'Create a TXT record for your domain starting with "v=spf1".',
            'Example: "v=spf1 include:_spf.google.com ~all"',
            "Test your SPF record before deploying to production.",
          ],
        };
      }
      throw error;
    }

    const flatRecords = txtRecords.map((entry) => entry.join(""));
    const spfRecords = flatRecords.filter((txt) =>
      txt.toLowerCase().startsWith("v=spf1")
    );

    // Check for critical errors first
    if (spfRecords.length === 0) {
      return {
        success: false,
        error: "No SPF record found.",
        domain,
        recommendations: [
          'Create a TXT record for your domain starting with "v=spf1".',
          'Example: "v=spf1 include:_spf.google.com ~all"',
          "Test your SPF record before deploying to production.",
        ],
      };
    }

    if (spfRecords.length > 1) {
      return {
        success: false,
        error: "Fatal: Multiple SPF records found.",
        domain,
        rawRecord: spfRecords.join(" | "),
        recommendations: [
          "A domain MUST NOT have multiple SPF records as per RFC 7208.",
          'Merge all mechanisms into a single "v=spf1" record.',
          "Remove duplicate or conflicting SPF records immediately.",
        ],
        warnings: [
          "Multiple SPF records will cause authentication failures.",
          "Email delivery may be severely impacted.",
        ],
      };
    }

    const spfRecord = spfRecords[0];
    const testIPs = [
      "8.8.8.8", // Google DNS (commonly used for testing)
      "1.1.1.1", // Cloudflare DNS
      "208.67.222.222", // OpenDNS
      "64.233.160.1", // Google mail server range
    ];

    const spfResults = [];

    // Test with multiple IPs to show how SPF varies
    for (const testIP of testIPs) {
      try {
        const spfResult = await spf({
          sender: `test@${domain}`,
          ip: testIP,
          helo: `mail.${domain}`,
          mta: "spf-analyzer.bluefox.email",
          resolver: customResolver,
        });

        spfResults.push({
          ip: testIP,
          result: spfResult.status,
          explanation: spfResult.comment || spfResult.explanation,
          details: spfResult,
        });
      } catch (error) {
        spfResults.push({
          ip: testIP,
          result: "error",
          explanation: `Error testing with IP ${testIP}: ${error.message}`,
          details: null,
        });
      }
    }

    // Use the first successful result for primary analysis
    const primaryResult = spfResults.find(
      (r) => r.details && r.result !== "error"
    )?.details;

    // Perform additional analysis on the raw record
    const analysis = await _analyzeSpfRecord(spfRecord, domain);

    // Combine mailauth results with our custom analysis
    return {
      success: true,
      domain,
      rawRecord: spfRecord,
      lookups: analysis.lookups,
      policy: analysis.policy,
      warnings: analysis.warnings,
      recommendations: analysis.recommendations,
      mechanisms: analysis.mechanisms,
      ipTestResults: spfResults, // Multiple IP test results
      mailauthResult: primaryResult
        ? {
            status: primaryResult.status,
            explanation:
              primaryResult.comment ||
              primaryResult.explanation ||
              "No additional explanation available",
            details: primaryResult,
          }
        : {
            status: "error",
            explanation: "Unable to perform SPF analysis with any test IP",
            details: null,
          },
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      domain,
      recommendations: [
        "Check your DNS configuration.",
        "Ensure your domain is properly configured.",
        "Try again in a few minutes if this is a temporary DNS issue.",
      ],
    };
  }
}

/**
 * Custom analysis function to extract detailed SPF information
 */
async function _analyzeSpfRecord(record, domain) {
  const mechanisms = record.split(/\s+/).slice(1); // Remove 'v=spf1'
  const analysis = {
    lookups: 0,
    warnings: [],
    recommendations: [],
    policy: null,
    mechanisms: [],
  };

  // Find the policy mechanism (usually ending with 'all')
  const policyMechanism = mechanisms.find((m) =>
    m.toLowerCase().includes("all")
  );
  analysis.policy = policyMechanism || "No policy specified";

  // Analyze policy strength
  if (!policyMechanism) {
    analysis.warnings.push(
      'Record does not contain a terminating "all" mechanism.'
    );
    analysis.recommendations.push(
      'Add "-all" (fail), "~all" (softfail), or "?all" (neutral) to specify a default policy.'
    );
  } else {
    const policyLower = policyMechanism.toLowerCase();
    if (policyLower === "+all") {
      analysis.warnings.push(
        'The "+all" mechanism is highly discouraged as it allows any server to send email.'
      );
      analysis.recommendations.push(
        'Replace "+all" with "-all" for strict policy or "~all" for gradual deployment.'
      );
    } else if (policyLower === "?all") {
      analysis.warnings.push(
        'Neutral policy "?all" provides no protection against spoofing.'
      );
      analysis.recommendations.push(
        'Consider using "~all" (softfail) or "-all" (fail) for better security.'
      );
    } else if (policyLower === "~all") {
      analysis.recommendations.push(
        'Good: Using "~all" allows gradual SPF deployment. Consider "-all" for stricter security once confident.'
      );
    } else if (policyLower === "-all") {
      analysis.recommendations.push(
        'Excellent: Using "-all" provides the strongest SPF protection.'
      );
    }
  }

  // Count DNS lookups and analyze mechanisms
  for (const mechanism of mechanisms) {
    const mechLower = mechanism.toLowerCase();
    const type = mechLower.split(":")[0].split("/")[0].split("=")[0];

    analysis.mechanisms.push({
      original: mechanism,
      type: type,
      requiresLookup: ["include", "a", "mx", "exists", "redirect"].includes(
        type
      ),
    });

    // Count DNS lookups
    if (["include", "a", "mx", "exists"].includes(type)) {
      analysis.lookups++;
    }

    // Check for redirect
    if (type === "redirect") {
      analysis.lookups++;
      const redirectDomain = mechanism.split("=")[1];
      if (redirectDomain) {
        analysis.recommendations.push(
          `Redirect to ${redirectDomain} detected. Ensure the target domain has a valid SPF record.`
        );
      }
    }

    // Check for deprecated mechanisms
    if (type === "ptr") {
      analysis.warnings.push(
        'The "ptr" mechanism is deprecated and should not be used (RFC 7208).'
      );
      analysis.recommendations.push(
        'Remove the "ptr" mechanism. Use "a", "mx", or "ip4/ip6" instead.'
      );
    }

    // Check for common issues
    if (type === "mx" && !mechanism.includes(":")) {
      analysis.recommendations.push(
        'Using bare "mx" mechanism. Consider specifying MX records explicitly for better performance.'
      );
    }

    if (type === "a" && !mechanism.includes(":")) {
      analysis.recommendations.push(
        'Using bare "a" mechanism. Consider specifying A records explicitly for better performance.'
      );
    }
  }

  // DNS lookup limit analysis
  if (analysis.lookups > 10) {
    analysis.warnings.unshift(
      `Fatal: Exceeded 10 DNS lookup limit. Found ${analysis.lookups} lookups (RFC 7208).`
    );
    analysis.recommendations.unshift(
      "Reduce DNS lookups by: 1) Flattening SPF records, 2) Using IP ranges instead of includes, 3) Consolidating mechanisms."
    );
  } else if (analysis.lookups > 8) {
    analysis.warnings.push(
      `Approaching DNS lookup limit: ${analysis.lookups}/10 lookups used.`
    );
    analysis.recommendations.push(
      "Consider optimizing your SPF record to reduce DNS lookups before hitting the limit."
    );
  } else if (analysis.lookups > 5) {
    analysis.recommendations.push(
      `Currently using ${analysis.lookups}/10 DNS lookups. Monitor this as you add more mechanisms.`
    );
  }

  // Record length analysis
  if (record.length > 255) {
    analysis.warnings.push(
      "SPF record exceeds 255 characters. This may cause DNS issues."
    );
    analysis.recommendations.push(
      "Shorten your SPF record by using shorter domain names or consolidating mechanisms."
    );
  }

  // Check for include loops (basic check)
  const includes = mechanisms
    .filter((m) => m.toLowerCase().startsWith("include:"))
    .map((m) => m.split(":")[1]);

  if (includes.includes(domain)) {
    analysis.warnings.push(
      "Potential SPF include loop detected (domain includes itself)."
    );
    analysis.recommendations.push(
      "Remove self-referential includes to prevent infinite loops."
    );
  }

  return analysis;
}
