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

		/**
		 * Add 1 point if the website has a valid SSL certificate.
		 */
		if (!empty($scanResults['hasSSL'])) {
			$score++;
		}
		$max++;

		/**
		 * Add 1 point if the website uses X-Frame-Options (protects against clickjacking).
		 */
		if (!empty($scanResults['has_x_frame_options'])) {
			$score++;
		}
		$max++;

		/**
		 * If no checks are available, return 0 to avoid division by zero.
		 */
		if ($max === 0) {
			return 0;
		}

		return (int) round(($score / $max) * 100);
	}
}
