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
	public static function calculateScore(array $scanResults, $speedMs = null): int
	{
		$score = 0;
		$max = 10; // number of checks

		// 1. HTTPS
		if (!empty($scanResults['https'])) $score++;

		// 2. HSTS
		if (!empty($scanResults['has_hsts'])) $score++;

		// 3. CSP
		if (!empty($scanResults['has_csp'])) $score++;

		// 4. X-Frame-Options
		if (!empty($scanResults['has_x_frame_options'])) $score++;

		// 5. X-Content-Type-Options
		if (!empty($scanResults['has_x_content_type_options'])) $score++;

		// 6. TLS version (require at least TLS 1.2)
		if (!empty($scanResults['tls_version']) && preg_match('/1\.(2|3)/', $scanResults['tls_version'])) $score++;

		// 7. SSL expiry (must be in the future)
		if (!empty($scanResults['ssl_expiry_date'])) {
			$expiry = strtotime($scanResults['ssl_expiry_date']);
			if ($expiry && $expiry > time()) $score++;
		}

		// 8. DNS SPF
		if (!empty($scanResults['dns_spf'])) $score++;

		// 9. DNS DKIM
		if (!empty($scanResults['dns_dkim'])) $score++;

		// 10. Speed (under 3000ms)
		if ($speedMs !== null && $speedMs <= 3000) $score++;

		// Return as 0-100
		return (int) round(($score / $max) * 100);
	}
}
