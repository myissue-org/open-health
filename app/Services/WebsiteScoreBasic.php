<?php

namespace App\Services;

class WebsiteScoreBasic
{
	/**
	 * Calculate a security score (0-100) based on scan results and speed.
	 * @param array $scanResults
	 * @param int|null $speedMs
	 * @return int
	 */
	public static function calculateScore(array $scanResults)
	{
		$score = 0;
		$max = 0;

		$passedChecks = [];
		$failedChecks = [];


		/**
		 * SSL (Secure Sockets Layer) ensures that data transferred between the
		 * website and its visitors is encrypted. This prevents attackers from
		 * intercepting sensitive information such as login credentials or
		 * payment details. A site with SSL (https://) is awarded 1 point.
		 */
		if (array_key_exists('https', $scanResults)) {
			if (!empty($scanResults['https'])) {
				$score++;
				$passedChecks[] = 'https';
			} else {
				$failedChecks[] = 'https';
			}
			$max++;  // Always increment max, so missing it lowers the score
		}

		/**
		 * X-Frame-Options is a response header that helps protect websites
		 * against clickjacking attacks. It controls whether the site can be
		 * embedded in an iframe on another domain. Enabling this header reduces
		 * the risk of malicious overlays tricking users into unintended clicks.
		 * If present, the site is awarded 1 point.
		 */
		if (array_key_exists('has_x_frame_options', $scanResults)) {
			if (!empty($scanResults['has_x_frame_options'])) {
				$score++;
				$passedChecks[] = 'has_x_frame_options';
			} else {
				$failedChecks[] = 'has_x_frame_options';
			}
			$max++;  // Always increment max, so missing it lowers the score
		}


		/**
		 * Only add DNS A record to the score if present, so missing it doesn't penalize.
		 * Purpose: The DNS A record ensures the domain resolves to an IPv4 address, which is required for most web traffic.
		 * Note: Some domains may not have an A record if they are not intended to be accessed via IPv4, or are used for other purposes.
		 * Automated scans may report 'false' for A record even on domains that are secure or used only for IPv6.
		 * So scoring strictly on A record will unfairly penalize them. This is a common issue in automated security scoring.
		 */
		if (array_key_exists('dns_a_record', $scanResults)) {
			if (!empty($scanResults['dns_a_record'])) {
				$score++;
				$passedChecks[] = 'dns_a_record';
			} else {
				$failedChecks[] = 'dns_a_record';
			}
			$max++; // Always increment max, so missing it lowers the score
		}

		/**
		 * Only add DNS AAAA record to the score if present, so missing it doesn't penalize.
		 * Purpose: The DNS AAAA record ensures the domain resolves to an IPv6 address, supporting modern network infrastructure.
		 * Note: Many domains do not have an AAAA record if they do not support IPv6, which is still common and not a security risk.
		 * Automated scans may report 'false' for AAAA record even on secure, well-maintained sites.
		 * So scoring strictly on AAAA record will unfairly penalize them. This is a common issue in automated security scoring.
		 */
		if (array_key_exists('dns_aaaa_record', $scanResults)) {
			if (!empty($scanResults['dns_aaaa_record'])) {
				$score++;
				$max++;
				$passedChecks[] = 'dns_aaaa_record';
			}
			// If AAAA record is missing, don't increment $max
		}



		/**
		 * Only add CSP (Content Security Policy) to the score if present, so missing 
		 * CSP (Content Security Policy) doesn't penalize.
		 * Purpose: CSP helps prevent cross-site scripting (XSS), clickjacking, and other code injection attacks
		 * by specifying which dynamic resources are allowed to load.
		 * Note: Many large sites like google.com do not send a Content-Security-Policy header to all user agents,
		 * often due to legacy browser support, complex infrastructure, or because they use other security mechanisms.
		 * As a result, automated scans may report 'false' for CSP even on secure, well-maintained sites.
		 * So scoring strictly on CSP will unfairly penalize them. This is a common issue in automated security scoring.
		 */
		if (array_key_exists('has_csp', $scanResults)) {
			if (!empty($scanResults['has_csp'])) {
				$score++;
				$max++;
				$passedChecks[] = 'has_csp';
			}
			// If CSP is missing, don't increment $max
		}

		/**
		 * Only add HSTS (Strict-Transport-Security) to the score if present, so missing HSTS doesn't penalize.
		 * Purpose: HSTS forces browsers to use HTTPS, protecting users from protocol downgrade attacks and cookie hijacking.
		 * Note: Many large sites like google.com do not send a Strict-Transport-Security header to all user agents,
		 * sometimes only sending it to specific regions, browsers, or over HTTPS. This is often due to compatibility,
		 * infrastructure, or deployment strategies. As a result, automated scans may report 'false' for HSTS even on
		 * secure sites. So scoring strictly on HSTS will unfairly penalize them. This is a common issue in automated security scoring.
		 */
		if (array_key_exists('has_hsts', $scanResults)) {
			if (!empty($scanResults['has_hsts'])) {
				$score++;
				$max++;
				$passedChecks[] = 'has_hsts';
			}
			// If HSTS is missing, don't increment $max
		}

		/**
		 * Only add X-Content-Type-Options to the score if present, so missing it doesn't penalize.
		 * Purpose: This header prevents browsers from interpreting files as a different MIME type, which helps prevent attacks.
		 * Note: Many large sites like google.com do not send X-Content-Type-Options to all user agents,
		 * often due to legacy support, infrastructure, or deployment strategies. Automated scans may report 'false'
		 * even on secure sites. So scoring strictly on this header will unfairly penalize them.
		 */
		if (array_key_exists('has_x_content_type_options', $scanResults)) {
			if (!empty($scanResults['has_x_content_type_options'])) {
				$score++;
				$max++;
				$passedChecks[] = 'has_x_content_type_options';
			}
			// If X-Content-Type-Options is missing, don't increment $max
		}

		/**
		 * Only add SPF (Sender Policy Framework) to the score if present, so missing SPF doesn't penalize.
		 * Purpose: SPF helps prevent email spoofing by specifying which mail servers are allowed to send email for the domain.
		 * Note: Many large sites like google.com do not publish SPF records on their main domain, or use other mechanisms.
		 * Automated scans may report 'false' for SPF even on secure, well-maintained sites.
		 * So scoring strictly on SPF will unfairly penalize them. This is a common issue in automated security scoring.
		 */
		if (array_key_exists('dns_spf', $scanResults)) {
			if (!empty($scanResults['dns_spf'])) {
				$score++;
				$max++;
				$passedChecks[] = 'dns_spf';
			}
			// If SPF is missing, don't increment $max
		}

		/**
		 * Only add DKIM (DomainKeys Identified Mail) to the score if present, so missing DKIM doesn't penalize.
		 * Purpose: DKIM helps prevent email spoofing by allowing the receiver to check that an email was indeed sent and authorized by the owner of that domain.
		 * Note: Many large sites like google.com do not publish DKIM records on their main domain, or use subdomains or other mechanisms.
		 * Automated scans may report 'false' for DKIM even on secure, well-maintained sites.
		 * So scoring strictly on DKIM will unfairly penalize them. This is a common issue in automated security scoring.
		 */
		if (array_key_exists('dns_dkim', $scanResults)) {
			if (!empty($scanResults['dns_dkim'])) {
				$score++;
				$max++;
				$passedChecks[] = 'dns_dkim';
			}
			// If DKIM is missing, don't increment $max
		}


		/**
		 * Only add DMARC (Domain-based Message Authentication, Reporting, and Conformance) to the score if present, so missing DMARC doesn't penalize.
		 * Purpose: DMARC helps prevent email spoofing by allowing domain owners to specify how unauthenticated emails should be handled.
		 * Note: Many large sites like google.com do not publish DMARC records on their main domain, or use subdomains or other mechanisms.
		 * Automated scans may report 'false' for DMARC even on secure, well-maintained sites.
		 * So scoring strictly on DMARC will unfairly penalize them. This is a common issue in automated security scoring.
		 */
		if (array_key_exists('dns_dmarc', $scanResults)) {
			if (!empty($scanResults['dns_dmarc'])) {
				$score++;
				$max++;
				$passedChecks[] = 'dns_dmarc';
			}
			// If DMARC is missing, don't increment $max
		}

		/**
		 * If no checks are available, return 0 to avoid division by zero.
		 */
		if ($max === 0) {
			return [
				'score' => 0,
				'passed_checks' => [],
				'failed_checks' => [],
			];
		}

		return [
			'score' => (int) round(($score / $max) * 100),
			'passed_checks' => $passedChecks,
			'failed_checks' => $failedChecks,
		];
	}
}
