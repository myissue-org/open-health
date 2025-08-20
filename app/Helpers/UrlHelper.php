<?php

namespace App\Helpers;

class UrlHelper
{


	/**
	 * Removes 'www.' from the beginning of a URL string if present.
	 *
	 * @param string $url
	 * @return string
	 */
	public static function removeWww($url)
	{
		return preg_replace('#^www\\.#', '', $url);
	}


	/**
	 * Normalizes a URL by converting to lowercase, removing the scheme (http/https),
	 * removing 'www.' if present, and trimming any trailing slash.
	 *
	 * @param string $url
	 * @return string
	 */
	public static function normalizeUrl($url)
	{
		$url = strtolower(trim($url));
		$url = preg_replace('#^https?://#', '', $url);
		$url = self::removeWww($url);
		$url = rtrim($url, '/');
		return $url;
	}


	/**
	 * Returns the scheme ('http' or 'https') of a URL, or null if not present.
	 *
	 * @param string $url
	 * @return string|null
	 */
	public static function getScheme($url)
	{
		$url = trim($url);
		if (stripos($url, 'https://') === 0) {
			return 'https';
		}
		if (stripos($url, 'http://') === 0) {
			return 'http';
		}
		return null; // or 'unknown'
	}
}
