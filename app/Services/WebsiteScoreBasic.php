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

		return $scanResults['hasSSL'];


		// Is served over HTTPS (SSL)
		if ($scanResults) {
			$max++;
			$score++;
		}



		// Return as 0-100, avoid division by zero
		if ($max === 0) {
			return 0;
		};

		return (int) round(($score / $max) * 100);
	}
}
