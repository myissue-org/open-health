<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;


class WebsiteSecurityScanner
{
	/**

	 * =========================
	 * Network Call Summary:
	 * =========================
	 *
	 * 1. cURL call
	 *    - Checks if the site is accessible over HTTPS (SSL).
	 *
	 * 2. stream_socket_client call (conditional)
	 *    - Fetches SSL certificate details (only if HTTPS is available).
	 *
	 * 3. get_headers call
	 *    - Fetches all HTTP headers for security checks.
	 *
	 * 4. dns_get_record calls
	 *    - One for A record
	 *    - One for AAAA record
	 *    - One for TXT record (to check SPF, DKIM, DMARC)
	 *
	 * ----------------------------------------------------------
	 * In total, this method makes at least 4 different types of
	 * network calls, and up to 6 actual network requests if all
	 * are executed. Each is needed for a different aspect of the
	 * website security scan.
	 * =========================
	 * @param string $url
	 * @return array
	 */
	public function scan(string $url): array
	{
		$scheme = parse_url($url, PHP_URL_SCHEME);
		$host = parse_url($url, PHP_URL_HOST);


		/**
		 * 1. HTTPS check (network call)
		 * 		- Check if the given $url is served over HTTPS (SSL)
		 *    - Purpose: To determine if the site is accessible over HTTPS (SSL).
		 *    - Why: Needed to know if the site supports SSL and to proceed with SSL info fetch.
		 */
		$httpsUrl = preg_replace("/^http:/i", "https:", $url);
		$ch = curl_init($httpsUrl);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_TIMEOUT, 10);
		$start = microtime(true);
		$result = curl_exec($ch);
		$end = microtime(true);
		$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		$error = curl_error($ch);
		curl_close($ch);

		$speedMs = (int)(($end - $start) * 1000);
		$https = ($result !== false && $httpCode >= 200 && $httpCode < 400);

		if ($error) {
			Log::warning("SSL check cURL error for $httpsUrl: $error");
		}

		/**
		 * 2. SSL certificate fetch (network call, only if HTTPS is available)
		 *    - Purpose: To retrieve SSL certificate details (expiry date, TLS version).
		 *    - Why: cURL cannot fetch certificate info; stream_socket_client is required.
		 */
		$tls_version = null;
		$ssl_expiry_date = null;
		if ($https && $host) {
			$context = stream_context_create(['ssl' => ['capture_peer_cert' => true]]);
			$client = @stream_socket_client("ssl://$host:443", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $context);
			if ($client) {
				$params = stream_context_get_params($client);
				if (isset($params['options']['ssl']['peer_certificate'])) {
					$cert = $params['options']['ssl']['peer_certificate'];
					$certInfo = openssl_x509_parse($cert);
					if (isset($certInfo['validTo_time_t'])) {
						$ssl_expiry_date = date('Y-m-d', $certInfo['validTo_time_t']);
					}
					if (isset($certInfo['extensions']['tlsfeature'])) {
						$tls_version = $certInfo['extensions']['tlsfeature'];
					} else {
						$tls_version = 'TLS'; // fallback
					}
				}
			}
		}

		/**
		 * 3. HTTP headers fetch (network call)
		 *    - Purpose: To collect security-related HTTP headers.
		 *    - Why: Used to check for headers like CSP, HSTS, X-Frame-Options, etc.
		 */
		$headers = @get_headers($url, 1);
		$server_header = $headers['Server'] ?? null;
		$has_csp = false;
		$has_x_frame_options = false;
		$has_hsts = false;
		$has_x_content_type_options = false;
		if ($headers && is_array($headers)) {
			foreach ($headers as $key => $value) {
				$k = strtolower($key);
				if ($k === 'content-security-policy') $has_csp = true;
				if ($k === 'x-frame-options') $has_x_frame_options = true;
				if ($k === 'strict-transport-security') $has_hsts = true;
				if ($k === 'x-content-type-options') $has_x_content_type_options = true;
			}
		}

		/**
		 * 4. DNS lookups (network calls)
		 *    - Purpose: To check for A, AAAA, SPF, DKIM, and DMARC DNS records.
		 *    - Why: These records are important for email and domain security.
		 */
		$dns_a_record = dns_get_record($host, DNS_A) ? true : false;
		$dns_aaaa_record = dns_get_record($host, DNS_AAAA) ? true : false;
		$dns_spf = false;
		$dns_dkim = false;
		$dns_dmarc = false;
		$txts = dns_get_record($host, DNS_TXT);
		foreach ($txts as $txt) {
			if (isset($txt['txt'])) {
				if (stripos($txt['txt'], 'v=spf1') !== false) $dns_spf = true;
				if (stripos($txt['txt'], 'dkim') !== false) $dns_dkim = true;
				if (stripos($txt['txt'], 'v=DMARC1') !== false) $dns_dmarc = true;
			}
		}

		return [
			'server_header' => $server_header,
			'has_csp' => $has_csp,
			'has_x_frame_options' => $has_x_frame_options,
			'has_hsts' => $has_hsts,
			'has_x_content_type_options' => $has_x_content_type_options,
			'tls_version' => $tls_version,
			'ssl_expiry_date' => $ssl_expiry_date,
			'dns_a_record' => $dns_a_record,
			'dns_aaaa_record' => $dns_aaaa_record,
			'dns_spf' => $dns_spf,
			'dns_dkim' => $dns_dkim,
			'dns_dmarc' => $dns_dmarc,
			'https' => $https,
			'speedMs' => $speedMs,
		];
	}
}
