<?php

namespace App\Services;

class WebsiteSecurityScanner
{
	/**
	 * Scan a website for security headers, SSL info, and DNS records.
	 *
	 * @param string $url
	 * @return array
	 */
	public function scan(string $url): array
	{
		$scheme = parse_url($url, PHP_URL_SCHEME);

		// HTTP headers
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

		// SSL info
		$tls_version = null;
		$ssl_expiry_date = null;
		if ($scheme === 'https') {
			$host = parse_url($url, PHP_URL_HOST);
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

		// DNS records
		$host = parse_url($url, PHP_URL_HOST);
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
		];
	}
}
