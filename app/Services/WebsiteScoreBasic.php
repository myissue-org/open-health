<?php

namespace App\Services;

class WebsiteScoreBasic
{
	/**
	 * Calculate a security score (0-100) based on scan results and speed.
	 * @param array $scanResults
	 * @param int|null $speedMs
	 * @return array
	 */
	public static function calculateScore(array $scanResults)
	{
		$score = 0;
		$max = 0;

		$passedChecks = [];
		$failedChecks = [];

		/**
		 * HTTPS ensures that data transferred between the website and its visitors is encrypted.
		 */
		if (array_key_exists('https', $scanResults)) {
			if (!empty($scanResults['https'])) {
				$score++;
				$passedChecks['https'] = true; // Store value
			} else {
				$failedChecks['https'] = false; // Store value
			}
			$max++; // Always increment max, critical for security
		}

		/**
		 * Mixed content checks for HTTP resources loaded on an HTTPS site, which undermines encryption.
		 */
		if (array_key_exists('has_mixed_content', $scanResults)) {
			if (empty($scanResults['has_mixed_content'])) {
				$score++;
				$passedChecks['has_mixed_content'] = false; // False is passing for this check
			} else {
				$failedChecks['has_mixed_content'] = true; // True is failing
			}
			$max++; // Always increment max, critical for security
		}

		/**
		 * Outdated TLS versions (e.g., TLS 1.0 or 1.1) are vulnerable to attacks like BEAST or POODLE.
		 */
		if (array_key_exists('is_tls_outdated', $scanResults)) {
			if (empty($scanResults['is_tls_outdated'])) {
				$score++;
				$passedChecks['is_tls_outdated'] = false; // False is passing
			} else {
				$failedChecks['is_tls_outdated'] = true; // True is failing
			}
			$max++; // Always increment max, critical for security
		}

		/**
		 * Weak ciphers in TLS connections compromise encryption security.
		 */
		if (array_key_exists('has_weak_ciphers', $scanResults)) {
			if (empty($scanResults['has_weak_ciphers'])) {
				$score++;
				$max++;
				$passedChecks['has_weak_ciphers'] = false; // False is passing
			} else {
				$failedChecks['has_weak_ciphers'] = true; // True is failing
			}
		}

		/**
		 * SSL certificate expiring soon (e.g., within 30 days) disrupts access and trust.
		 */
		if (array_key_exists('is_ssl_expiring_soon', $scanResults)) {
			if (empty($scanResults['is_ssl_expiring_soon'])) {
				$score++;
				$max++;
				$passedChecks['is_ssl_expiring_soon'] = false; // False is passing
			} else {
				$failedChecks['is_ssl_expiring_soon'] = true; // True is failing
			}
		}

		/**
		 * Secure cookies ensure cookies are sent only over HTTPS, protecting against interception.
		 */
		if (array_key_exists('has_secure_cookies', $scanResults)) {
			if (!empty($scanResults['has_secure_cookies'])) {
				$score++;
				$max++;
				$passedChecks['has_secure_cookies'] = true; // True is passing
			} else {
				$failedChecks['has_secure_cookies'] = false; // False is failing
			}
		}

		/**
		 * HttpOnly cookies prevent JavaScript access, protecting against XSS attacks.
		 */
		if (array_key_exists('has_httponly_cookies', $scanResults)) {
			if (!empty($scanResults['has_httponly_cookies'])) {
				$score++;
				$max++;
				$passedChecks['has_httponly_cookies'] = true; // True is passing
			} else {
				$failedChecks['has_httponly_cookies'] = false; // False is failing
			}
		}

		/**
		 * SameSite cookies restrict cross-site requests, protecting against CSRF attacks.
		 */
		if (array_key_exists('has_samesite_cookies', $scanResults)) {
			if (!empty($scanResults['has_samesite_cookies'])) {
				$score++;
				$max++;
				$passedChecks['has_samesite_cookies'] = true; // True is passing
			} else {
				$failedChecks['has_samesite_cookies'] = false; // False is failing
			}
		}

		/**
		 * X-Frame-Options is a response header that helps protect websites against clickjacking attacks.
		 */
		if (array_key_exists('has_x_frame_options', $scanResults)) {
			if (!empty($scanResults['has_x_frame_options'])) {
				$score++;
				$passedChecks['has_x_frame_options'] = true; // True is passing
			} else {
				$failedChecks['has_x_frame_options'] = false; // False is failing
			}
			$max++; // Always increment max
		}

		/**
		 * DNS A record ensures the domain resolves to an IPv4 address, required for most web traffic.
		 */
		if (array_key_exists('dns_a_record', $scanResults)) {
			if (!empty($scanResults['dns_a_record'])) {
				$score++;
				$passedChecks['dns_a_record'] = true; // True is passing
			} else {
				$failedChecks['dns_a_record'] = false; // False is failing
			}
			$max++; // Always increment max
		}

		/**
		 * DNS AAAA record ensures the domain resolves to an IPv6 address, supporting modern network infrastructure.
		 */
		if (array_key_exists('dns_aaaa_record', $scanResults)) {
			if (!empty($scanResults['dns_aaaa_record'])) {
				$score++;
				$max++;
				$passedChecks['dns_aaaa_record'] = true; // True is passing
			} else {
				$failedChecks['dns_aaaa_record'] = false; // False is failing
			}
		}

		/**
		 * CSP (Content Security Policy) helps prevent XSS, clickjacking, and other code injection attacks.
		 */
		if (array_key_exists('has_csp', $scanResults)) {
			if (!empty($scanResults['has_csp'])) {
				$score++;
				$max++;
				$passedChecks['has_csp'] = true; // True is passing
			} else {
				$failedChecks['has_csp'] = false; // False is failing
			}
		}

		/**
		 * HSTS (Strict-Transport-Security) forces browsers to use HTTPS, protecting against downgrade attacks.
		 */
		if (array_key_exists('has_hsts', $scanResults)) {
			if (!empty($scanResults['has_hsts'])) {
				$score++;
				$max++;
				$passedChecks['has_hsts'] = true; // True is passing
			} else {
				$failedChecks['has_hsts'] = false; // False is failing
			}
		}

		/**
		 * X-Content-Type-Options prevents browsers from interpreting files as a different MIME type.
		 */
		if (array_key_exists('has_x_content_type_options', $scanResults)) {
			if (!empty($scanResults['has_x_content_type_options'])) {
				$score++;
				$max++;
				$passedChecks['has_x_content_type_options'] = true; // True is passing
			} else {
				$failedChecks['has_x_content_type_options'] = false; // False is failing
			}
		}

		/**
		 * SPF helps prevent email spoofing by specifying allowed mail servers.
		 */
		if (array_key_exists('dns_spf', $scanResults)) {
			if (!empty($scanResults['dns_spf'])) {
				$score++;
				$max++;
				$passedChecks['dns_spf'] = true; // True is passing
			} else {
				$failedChecks['dns_spf'] = false; // False is failing
			}
		}

		/**
		 * DKIM helps verify that an email was sent and authorized by the domain owner.
		 */
		if (array_key_exists('dns_dkim', $scanResults)) {
			if (!empty($scanResults['dns_dkim'])) {
				$score++;
				$max++;
				$passedChecks['dns_dkim'] = true; // True is passing
			} else {
				$failedChecks['dns_dkim'] = false; // False is failing
			}
		}

		/**
		 * DMARC allows domain owners to specify how unauthenticated emails should be handled.
		 */
		if (array_key_exists('dns_dmarc', $scanResults)) {
			if (!empty($scanResults['dns_dmarc'])) {
				$score++;
				$max++;
				$passedChecks['dns_dmarc'] = true; // True is passing
			} else {
				$failedChecks['dns_dmarc'] = false; // False is failing
			}
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
