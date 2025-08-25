<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreSecurityTestBasicRequest;
use App\Http\Requests\UpdateSecurityTestBasicRequest;
use App\Models\ScannedWebsiteBasic;
use App\Models\SecurityTestBasic;
use App\Helpers\UrlHelper;
use App\Services\WebsiteSecurityScanner;
use App\Services\WebsiteScoreBasic;
use Exception;
use Illuminate\Support\Facades\Log;

class SecurityTestBasicController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        //
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(StoreSecurityTestBasicRequest $request)
    {
        try {
            $title = $request->input('title');
            $url = $request->input('url');
            $first_name = $request->input('first_name');
            $last_name = $request->input('last_name');
            $email = $request->input('email');

            // Remove 'www.' from the beginning if present.
            $slug = UrlHelper::removeWww($url);

            // Normalizes a URL by converting to lowercase, removing the scheme (http/https),
            // removing 'www.' if present, and trimming any trailing slash.
            $normalizedUrl = UrlHelper::normalizeUrl($url);

            // Create or update the website by slug
            $website = ScannedWebsiteBasic::updateOrCreate(
                ['slug' => $normalizedUrl],
                ['url' => $url, 'title' => $title]
            );

            $scanner = new WebsiteSecurityScanner();
            $scanResults = $scanner->scan($url);

            // Check for scanner errors
            if ($scanResults['error']) {
                Log::error("Scanner error for URL {$url}: {$scanResults['error']}");
                return response()->json(['error' => 'Scan failed. The URL may not exist or is unreachable: ' . $scanResults['error']], 422);
            }

            // Derive passed and failed checks for response (if needed)
            $passedChecks = [];
            $failedChecks = [];


            foreach ($scanResults as $key => $value) {
                if (in_array($key, ['score', 'speedMs', 'tls_version', 'ssl_expiry_date', 'server_header', 'error', 'website_prefix'])) {
                    continue; // Skip non-boolean fields
                }
                if ($value === true && strpos($key, 'has_') === 0 && $key !== 'has_server_version_exposed' && $key !== 'has_permissive_cors' && $key !== 'has_mixed_content') {
                    $passedChecks[] = $key;
                } elseif ($value === false && strpos($key, 'has_') === 0 && $key !== 'has_server_version_exposed' && $key !== 'has_permissive_cors' && $key !== 'has_mixed_content') {
                    $failedChecks[] = $key;
                } elseif ($value === true && in_array($key, ['has_server_version_exposed', 'has_permissive_cors', 'has_mixed_content', 'is_tls_outdated', 'is_ssl_expiring_soon', 'is_csp_weak'])) {
                    $failedChecks[] = $key;
                } elseif ($value === false && $key === 'is_dmarc_strong') {
                    $failedChecks[] = $key;
                }
            }

            $scoreResult = WebsiteScoreBasic::calculateScore($scanResults);

            $score = $scoreResult['score'];
            $passedChecks = $scoreResult['passed_checks'];
            $failedChecks = $scoreResult['failed_checks'];

            $createdSecurityTest = SecurityTestBasic::create([
                'website_id' => $website->id,
                'score' => $score,
                'https' => $scanResults['https'] ?? false,
                'website_prefix' => $scanResults['https'] ? 'https' : 'http',
                'tls_version' => $scanResults['tls_version'],
                'is_tls_outdated' => $scanResults['is_tls_outdated'] ?? false,
                'ssl_expiry_date' => $scanResults['ssl_expiry_date'],
                'is_ssl_expiring_soon' => $scanResults['is_ssl_expiring_soon'] ?? false,
                'has_weak_ciphers' => $scanResults['has_weak_ciphers'] ?? false,
                'has_csp' => $scanResults['has_csp'] ?? false,
                'is_csp_weak' => $scanResults['is_csp_weak'] ?? false,
                'has_x_frame_options' => $scanResults['has_x_frame_options'] ?? false,
                'has_hsts' => $scanResults['has_hsts'] ?? false,
                'is_hsts_preloaded' => $scanResults['is_hsts_preloaded'] ?? false,
                'has_x_content_type_options' => $scanResults['has_x_content_type_options'] ?? false,
                'has_permissive_cors' => $scanResults['has_permissive_cors'] ?? false,
                'has_secure_cookies' => $scanResults['has_secure_cookies'] ?? true,
                'has_httponly_cookies' => $scanResults['has_httponly_cookies'] ?? true,
                'has_samesite_cookies' => $scanResults['has_samesite_cookies'] ?? true,
                'server_header' => $scanResults['server_header'],
                'has_server_version_exposed' => $scanResults['has_server_version_exposed'] ?? false,
                'speed_ms' => $scanResults['speedMs'],
                'dns_a_record' => $scanResults['dns_a_record'] ?? false,
                'dns_aaaa_record' => $scanResults['dns_aaaa_record'] ?? false,
                'dns_caa_record' => $scanResults['dns_caa_record'] ?? false,
                'dnssec_enabled' => $scanResults['dnssec_enabled'] ?? false,
                'dns_spf' => $scanResults['dns_spf'] ?? false,
                'dns_dkim' => $scanResults['dns_dkim'] ?? false,
                'dns_dmarc' => $scanResults['dns_dmarc'] ?? false,
                'is_dmarc_strong' => $scanResults['is_dmarc_strong'] ?? false,
                'has_mixed_content' => $scanResults['has_mixed_content'] ?? false,
                'has_sri' => $scanResults['has_sri'] ?? true,
                'has_http_redirect' => $scanResults['has_http_redirect'] ?? false,
                'error' => $scanResults['error'],
                'first_name' => $first_name,
                'last_name' => $last_name,
                'email' => $email,
            ]);

            $createdSecurityTest->load('website');
            $response = $createdSecurityTest->fresh()->load('website')->toArray();


            // Get the latest 10 tests for this website
            $latestTests = SecurityTestBasic::with('website')
                ->where('website_id', $website->id)
                ->orderByDesc('test_ran_at')
                ->take(10)
                ->get();

            return response()->json([
                'created_test' => $response,
                'latest_tests' => $latestTests,
                'passedChecks' => $passedChecks,
                'failedChecks' => $failedChecks,
            ], 201);
        } catch (Exception $e) {
            Log::error("Failed to store security test for URL {$url}: {$e->getMessage()}");
            return response()->json(['error' => 'Failed to process scan'], 500);
        }
    }

    /**
     * Display the specified resource with its related website.
     */
    public function show(SecurityTestBasic $securityTestBasic)
    {
        // Eager load the related website
        $securityTestBasic->load('website');

        if (!$securityTestBasic->website) {
            return response()->json(['error' => 'Related website not found.'], 404);
        }

        // Get the latest 10 tests for this website (by website_id)
        $latestTests = SecurityTestBasic::with('website')
            ->where('website_id', $securityTestBasic->website_id)
            ->orderByDesc('test_ran_at')
            ->take(10)
            ->get();

        $scoreResult = WebsiteScoreBasic::calculateScore($securityTestBasic->toArray());
        $passedChecks = $scoreResult['passed_checks'];
        $failedChecks = $scoreResult['failed_checks'];

        return response()->json([
            'created_test' => $securityTestBasic,
            'latest_tests' => $latestTests,
            'passedChecks' => $passedChecks,
            'failedChecks' => $failedChecks,
        ]);
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(SecurityTestBasic $securityTestBasic)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(UpdateSecurityTestBasicRequest $request, SecurityTestBasic $securityTestBasic)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(SecurityTestBasic $securityTestBasic)
    {
        //
    }
}
