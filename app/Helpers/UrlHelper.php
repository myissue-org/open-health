<?php

namespace App\Helpers;

class UrlHelper
{
	public static function normalizeUrl($url)
	{
		$url = strtolower(trim($url));
		$url = preg_replace('#^https?://#', '', $url);
		$url = preg_replace('#^www\\.#', '', $url);
		$url = rtrim($url, '/');
		return $url;
	}

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
