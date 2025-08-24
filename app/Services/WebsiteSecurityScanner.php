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
	 * 1. cURL call (HTTPS check)
	 *    - Checks if the site is accessible over HTTPS (SSL).
	 *
	 * 2. stream_socket_client call (conditional)
	 *    - Fetches SSL certificate details (only if HTTPS is available).
	 *
	 * 3. get_headers call
	 *    - Fetches all HTTP headers for security checks, including cookies.
	 *
	 * 4. cURL call (mixed content and SRI check)
	 *    - Fetches page content to detect insecure resources and SRI usage.
	 *
	 * 5. cURL call (HTTP to HTTPS redirect check)
	 *    - Checks if HTTP redirects to HTTPS.
	 *
	 * 6. cURL call (HSTS preload check)
	 *    - Checks if the domain is on the HSTS preload list.
	 *
	 * 7. dns_get_record calls
	 *    - One for A record
	 *    - One for AAAA record
	 *    - One for TXT record (SPF, DKIM, DMARC)
	 *    - One for CAA record
	 *    - One for DS/DNSKEY record (DNSSEC)
	 *
	 * ----------------------------------------------------------
	 * In total, this method makes at least 7 different types of
	 * network calls, and up to 10 actual network requests if all
	 * are executed. Each is needed for a different aspect of the
	 * website security scan.
	 * =========================
	 * @param string $url
	 * @return array
	 */
	public function scan(string $url): array
	{
		/**
		 * Input validation
		 *    - Purpose: To validate the input URL and host before proceeding with scans.
		 *    - Why: Prevents errors from malformed URLs or invalid hosts.
		 */
		if (!filter_var($url, FILTER_VALIDATE_URL)) {
			Log::error("Invalid URL provided: $url");
			return [
				'error' => 'Invalid URL',
				'server_header' => null,
				'has_server_version_exposed' => false,
				'has_csp' => false,
				'is_csp_weak' => false,
				'has_x_frame_options' => false,
				'has_hsts' => false,
				'is_hsts_preloaded' => false,
				'has_x_content_type_options' => false,
				'has_permissive_cors' => false,
				'tls_version' => null,
				'ssl_expiry_date' => null,
				'is_tls_outdated' => false,
				'is_ssl_expiring_soon' => false,
				'has_weak_ciphers' => false,
				'dns_a_record' => false,
				'dns_aaaa_record' => false,
				'dns_caa_record' => false,
				'dnssec_enabled' => false,
				'dns_spf' => false,
				'dns_dkim' => false,
				'dns_dmarc' => false,
				'is_dmarc_strong' => false,
				'has_mixed_content' => false,
				'has_sri' => true,
				'has_http_redirect' => false,
				'has_secure_cookies' => true,
				'has_httponly_cookies' => true,
				'has_samesite_cookies' => true,
				'speedMs' => 0,
			];
		}
		$scheme = parse_url($url, PHP_URL_SCHEME);
		$host = parse_url($url, PHP_URL_HOST);
		if (!$host || !dns_get_record($host, DNS_A)) {
			Log::error("DNS resolution failed for host: $host");
			return [
				'error' => 'DNS resolution failed',
				'server_header' => null,
				'has_server_version_exposed' => false,
				'has_csp' => false,
				'is_csp_weak' => false,
				'has_x_frame_options' => false,
				'has_hsts' => false,
				'is_hsts_preloaded' => false,
				'has_x_content_type_options' => false,
				'has_permissive_cors' => false,
				'tls_version' => null,
				'ssl_expiry_date' => null,
				'is_tls_outdated' => false,
				'is_ssl_expiring_soon' => false,
				'has_weak_ciphers' => false,
				'dns_a_record' => false,
				'dns_aaaa_record' => false,
				'dns_caa_record' => false,
				'dnssec_enabled' => false,
				'dns_spf' => false,
				'dns_dkim' => false,
				'dns_dmarc' => false,
				'is_dmarc_strong' => false,
				'has_mixed_content' => false,
				'has_sri' => true,
				'has_http_redirect' => false,
				'has_secure_cookies' => true,
				'has_httponly_cookies' => true,
				'has_samesite_cookies' => true,
				'https' => false,
				'speedMs' => 0,
			];
		}

		/**
		 * 1. HTTPS check (network call)
		 *    - Purpose: To determine if the site is accessible over HTTPS (SSL).
		 *    - Why: Needed to know if the site supports SSL and to proceed with SSL info fetch.
		 */
		$httpsUrl = preg_replace("/^http:/i", "https:", $url);
		$maxRetries = 2;
		$retryCount = 0;
		$https = false;
		$speedMs = 0;
		$error = null;
		$httpCode = 0;
		$redirectUrl = null;

		while ($retryCount <= $maxRetries && !$https) {
			$ch = curl_init($httpsUrl);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_TIMEOUT, 30);
			curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36');
			curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
			curl_setopt($ch, CURLOPT_VERBOSE, true);
			curl_setopt($ch, CURLOPT_HTTPHEADER, [
				'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
				'Accept-Language: en-US,en;q=0.5',
				'Connection: keep-alive'
			]);
			$verbose = fopen('php://temp', 'w+');
			curl_setopt($ch, CURLOPT_STDERR, $verbose);
			$start = microtime(true);
			$result = curl_exec($ch);
			$end = microtime(true);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
			$redirectUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
			$error = curl_error($ch);
			$curlErrno = curl_errno($ch);
			$sslVerified = curl_getinfo($ch, CURLINFO_SSL_VERIFYRESULT) === 0; // Check SSL verification
			curl_close($ch);

			$body = $result;
			$speedMs = (int)(($end - $start) * 1000);
			// Consider HTTPS valid if SSL handshake succeeded, even for non-standard status codes like 455
			$https = ($result !== false && $sslVerified && ($httpCode >= 200 && $httpCode < 400 || $httpCode === 455));

			// Debug logging
			rewind($verbose);
			$verboseLog = stream_get_contents($verbose);
			fclose($verbose);
			Log::debug("HTTPS check for $httpsUrl (Attempt " . ($retryCount + 1) . "): HTTP code: $httpCode, Result: " . ($result !== false ? 'Success' : 'Failed') . ", SSL Verified: " . ($sslVerified ? 'Yes' : 'No') . ", Error: " . ($error ?: 'None') . ", cURL errno: $curlErrno, Redirect URL: $redirectUrl, Speed: $speedMs ms");
			Log::debug("Verbose cURL output for $httpsUrl: $verboseLog");

			if ($error) {
				Log::warning("SSL check cURL error for $httpsUrl (Attempt " . ($retryCount + 1) . "): $error (cURL errno: $curlErrno, HTTP code: $httpCode)");
			}

			if (!$https && $retryCount < $maxRetries) {
				$retryCount++;
				sleep(1);
				continue;
			}
			break;
		}

		/**
		 * 2. SSL certificate fetch (network call, only if HTTPS is available)
		 *    - Purpose: To retrieve SSL certificate details, check for outdated TLS versions, warn about near-expiry certificates, and detect weak cipher suites.
		 *    - Why: cURL cannot fetch certificate info; stream_socket_client is required. Weak ciphers pose security risks.
		 */
		$tls_version = null;
		$ssl_expiry_date = null;
		$is_tls_outdated = false;
		$is_ssl_expiring_soon = false;
		$has_weak_ciphers = false;
		if ($https && $host) {
			$context = stream_context_create([
				'ssl' => [
					'capture_peer_cert' => true,
					'crypto_method' => STREAM_CRYPTO_METHOD_TLS_CLIENT
				]
			]);
			$client = @stream_socket_client("ssl://$host:443", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $context);
			if ($client) {
				$params = stream_context_get_params($client);
				if (isset($params['options']['ssl']['peer_certificate'])) {
					$cert = $params['options']['ssl']['peer_certificate'];
					$certInfo = openssl_x509_parse($cert);
					if (isset($certInfo['validTo_time_t'])) {
						$ssl_expiry_date = date('Y-m-d', $certInfo['validTo_time_t']);
						$expiry_time = $certInfo['validTo_time_t'];
						$days_until_expiry = ($expiry_time - time()) / (60 * 60 * 24);
						if ($days_until_expiry <= 30) {
							$is_ssl_expiring_soon = true;
						}
					}
					$tls_version = $params['options']['ssl']['crypto_method'] ?? 'Unknown';
					$tls_version_map = [
						STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT => 'TLSv1.0',
						STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT => 'TLSv1.1',
						STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT => 'TLSv1.2',
						STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT => 'TLSv1.3'
					];
					foreach ($tls_version_map as $method => $version) {
						if ($tls_version & $method) {
							$tls_version = $version;
							break;
						}
					}
					if (in_array($tls_version, ['TLSv1.0', 'TLSv1.1'])) {
						$is_tls_outdated = true;
					}
					$current_cipher = $params['options']['ssl']['cipher_name'] ?? '';
					$weak_ciphers = ['rc4', 'des', '3des', 'md5'];
					foreach ($weak_ciphers as $weak) {
						if (stripos($current_cipher, $weak) !== false) {
							$has_weak_ciphers = true;
							break;
						}
					}
				}
				fclose($client);
			}
		}

		/**
		 * 3. HTTP headers fetch (network call)
		 *    - Purpose: To collect security-related HTTP headers, check for server version exposure, detect CORS misconfigurations, evaluate CSP strength, and check cookie attributes.
		 *    - Why: Used to check for headers like CSP, HSTS, X-Frame-Options, cookies, etc., and identify risky configurations.
		 */
		$headers = @get_headers($url, 1);
		$server_header = null;
		$has_server_version_exposed = false;
		$has_csp = false;
		$is_csp_weak = false;
		$has_x_frame_options = false;
		$has_hsts = false;
		$has_x_content_type_options = false;
		$has_permissive_cors = false;
		$has_secure_cookies = true;
		$has_httponly_cookies = true;
		$has_samesite_cookies = true;
		if ($headers && is_array($headers)) {
			foreach ($headers as $key => $value) {
				$k = strtolower($key);
				if ($k === 'server') {
					// Handle array or string for Server header
					$server_header = is_array($value) ? implode(', ', $value) : $value;
					if (is_string($server_header) && preg_match('/\d+\.\d+\.\d+/', $server_header)) {
						$has_server_version_exposed = true;
					}
				}
				if ($k === 'content-security-policy') {
					$has_csp = true;
					if (is_string($value) && (stripos($value, 'unsafe-inline') !== false || stripos($value, 'unsafe-eval') !== false || stripos($value, '*') !== false)) {
						$is_csp_weak = true;
					}
				}
				if ($k === 'x-frame-options') $has_x_frame_options = true;
				if ($k === 'strict-transport-security') $has_hsts = true;
				if ($k === 'x-content-type-options') $has_x_content_type_options = true;
				if ($k === 'access-control-allow-origin' && (is_string($value) && $value === '*')) {
					$has_permissive_cors = true;
				}
			}
			if (isset($headers['Set-Cookie'])) {
				$cookies = is_array($headers['Set-Cookie']) ? $headers['Set-Cookie'] : [$headers['Set-Cookie']];
				foreach ($cookies as $cookie) {
					if (stripos($cookie, 'Secure') === false) {
						$has_secure_cookies = false;
					}
					if (stripos($cookie, 'HttpOnly') === false) {
						$has_httponly_cookies = false;
					}
					if (stripos($cookie, 'SameSite') === false) {
						$has_samesite_cookies = false;
					}
				}
			}
		}

		/**
		 * 4. Mixed content and SRI check (network call)
		 *    - Purpose: To detect if the HTTPS page loads insecure (HTTP) resources and check for Subresource Integrity (SRI) usage.
		 *    - Why: Mixed content and missing SRI can expose users to attacks.
		 */
		$has_mixed_content = false;
		$has_sri = true;
		if ($https) {
			$ch = curl_init($httpsUrl);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
			curl_setopt($ch, CURLOPT_TIMEOUT, 10);
			curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36');
			$pageContent = curl_exec($ch);
			$error = curl_error($ch);
			curl_close($ch);
			if ($pageContent && !$error) {
				if (preg_match('/(src|href)=[\'"]http:\/\/[^\'"]+/i', $pageContent)) {
					$has_mixed_content = true;
				}
				if (preg_match_all('/<(script|link)[^>]+(src|href)=[\'"](https?:\/\/[^\'"]+)[\'"][^>]*>/i', $pageContent, $matches)) {
					foreach ($matches[0] as $tag) {
						if (stripos($tag, 'integrity=') === false && stripos($tag, 'localhost') === false && stripos($tag, $host) === false) {
							$has_sri = false;
							break;
						}
					}
				}
			} else {
				Log::warning("Mixed content/SRI check cURL error for $httpsUrl: $error");
			}
		}

		/**
		 * 5. HTTP to HTTPS redirect check (network call)
		 *    - Purpose: To verify if HTTP requests redirect to HTTPS.
		 *    - Why: Lack of redirects can expose users to insecure connections.
		 */
		$has_http_redirect = false;
		$httpUrl = preg_replace("/^https:/i", "http:", $url);
		$ch = curl_init($httpUrl);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
		curl_setopt($ch, CURLOPT_HEADER, true);
		curl_setopt($ch, CURLOPT_NOBODY, true);
		curl_setopt($ch, CURLOPT_TIMEOUT, 10);
		curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36');
		curl_exec($ch);
		$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		$redirectUrl = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
		$error = curl_error($ch);
		curl_close($ch);
		if ($httpCode >= 301 && $httpCode <= 308 && $redirectUrl && stripos($redirectUrl, 'https://') === 0) {
			$has_http_redirect = true;
		}
		if ($error) {
			Log::warning("HTTP redirect check cURL error for $httpUrl: $error");
		}

		/**
		 * 6. HSTS preload check (network call)
		 *    - Purpose: To verify if the domain is on the HSTS preload list.
		 *    - Why: HSTS preload ensures browsers enforce HTTPS from the first visit.
		 */
		$is_hsts_preloaded = false;
		if ($has_hsts && $host) {
			$ch = curl_init("https://hstspreload.org/api/v2/status?domain=$host");
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_TIMEOUT, 5);
			curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36');
			$response = curl_exec($ch);
			$error = curl_error($ch);
			curl_close($ch);
			if ($response && !$error) {
				$data = json_decode($response, true);
				if (isset($data['status']) && $data['status'] === 'preloaded') {
					$is_hsts_preloaded = true;
				}
			} else {
				Log::warning("HSTS preload check cURL error for $host: $error");
			}
		}

		/**
		 * 7. DNS lookups (network calls)
		 *    - Purpose: To check for A, AAAA, SPF, DKIM, DMARC, CAA, and DNSSEC records, and evaluate DMARC policy strength.
		 *    - Why: These records are important for email, domain, certificate, and DNS security.
		 */
		$dns_a_record = false;
		$dns_aaaa_record = false;
		$dns_caa_record = false;
		$dnssec_enabled = false;
		$dns_spf = false;
		$dns_dkim = false;
		$dns_dmarc = false;
		$is_dmarc_strong = false;
		if ($host) {
			$dns_a_record = dns_get_record($host, DNS_A) ? true : false;
			if (!$dns_a_record) {
				Log::warning("DNS A record lookup failed for $host");
			}
			$dns_aaaa_record = dns_get_record($host, DNS_AAAA) ? true : false;
			if (!$dns_aaaa_record) {
				Log::warning("DNS AAAA record lookup failed for $host");
			}
			$dns_caa_record = dns_get_record($host, DNS_CAA) ? true : false;
			if (!$dns_caa_record) {
				Log::warning("DNS CAA record lookup failed for $host");
			}

			$txts = dns_get_record($host, DNS_TXT);
			if ($txts === false) {
				Log::warning("DNS TXT record lookup failed for $host");
			} else {
				foreach ($txts as $txt) {
					if (isset($txt['txt'])) {
						if (stripos($txt['txt'], 'v=spf1') !== false) $dns_spf = true;
						if (stripos($txt['txt'], 'dkim') !== false) $dns_dkim = true;
						if (stripos($txt['txt'], 'v=DMARC1') !== false) {
							$dns_dmarc = true;
							if (stripos($txt['txt'], 'p=reject') !== false || stripos($txt['txt'], 'p=quarantine') !== false) {
								$is_dmarc_strong = true;
							}
						}
					}
				}
			}
		}

		return [
			'error' => $error ?: null,
			'server_header' => $server_header,
			'has_server_version_exposed' => $has_server_version_exposed,
			'has_csp' => $has_csp,
			'is_csp_weak' => $is_csp_weak,
			'has_x_frame_options' => $has_x_frame_options,
			'has_hsts' => $has_hsts,
			'is_hsts_preloaded' => $is_hsts_preloaded,
			'has_x_content_type_options' => $has_x_content_type_options,
			'has_permissive_cors' => $has_permissive_cors,
			'tls_version' => $tls_version,
			'ssl_expiry_date' => $ssl_expiry_date,
			'is_tls_outdated' => $is_tls_outdated,
			'is_ssl_expiring_soon' => $is_ssl_expiring_soon,
			'has_weak_ciphers' => $has_weak_ciphers,
			'dns_a_record' => $dns_a_record,
			'dns_aaaa_record' => $dns_aaaa_record,
			'dns_caa_record' => $dns_caa_record,
			'dns_spf' => $dns_spf,
			'dns_dkim' => $dns_dkim,
			'dns_dmarc' => $dns_dmarc,
			'is_dmarc_strong' => $is_dmarc_strong,
			'has_mixed_content' => $has_mixed_content,
			'has_sri' => $has_sri,
			'has_http_redirect' => $has_http_redirect,
			'has_secure_cookies' => $has_secure_cookies,
			'has_httponly_cookies' => $has_httponly_cookies,
			'has_samesite_cookies' => $has_samesite_cookies,
			'https' => $https,
			'speedMs' => $speedMs,
			'first_name' => null, // Added to match database schema
			'last_name' => null,  // Added to match database schema
			'email' => null,      // Added to match database schema
		];
	}
}
