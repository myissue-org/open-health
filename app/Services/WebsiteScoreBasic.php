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

		if (!empty($scanResults['hasSSL'])) {
			$score++;
		}
		$max++;

		if (!empty($scanResults['has_x_frame_options'])) {
			$score++;
		}
		$max++;

		if ($max === 0) {
			return 0;
		}

		return (int) round(($score / $max) * 100);
	}
}
