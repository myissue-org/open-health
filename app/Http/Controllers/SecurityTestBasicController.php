<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreSecurityTestBasicRequest;
use App\Http\Requests\UpdateSecurityTestBasicRequest;
use App\Models\ScannedWebsiteBasic;
use App\Models\SecurityTestBasic;
use App\Helpers\UrlHelper;
use App\Services\WebsiteSecurityScanner;
use App\Services\WebsiteScoreBasic;

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
        $title = $request->input('title');
        $url = $request->input('url');
        $first_name = $request->input('first_name');
        $last_name = $request->input('last_name');
        $email = $request->input('email');

        // Remove 'www.' from the beginning if present.
        $slug = UrlHelper::removeWww($request->input('url'));

        //  Returns the scheme ('http' or 'https') of a URL, or null if not present.
        $scheme = UrlHelper::getScheme($request->input('url'));

        // Normalizes a URL by converting to lowercase, removing the scheme (http/https),
        // removing 'www.' if present, and trimming any trailing slash.
        $normalizedUrl = UrlHelper::normalizeUrl($request->input('url'));


        // Create or update the website by slug
        $website = ScannedWebsiteBasic::updateOrCreate(
            ['slug' => $normalizedUrl],
            ['url' => $url, 'title' => $title]
        );


        $scanner = new WebsiteSecurityScanner();



        $scanResults = $scanner->scan($url);

        // Flatten any array values in scanResults to strings (for DB columns)
        $fieldsToFlatten = [
            'tls_version',
            'ssl_expiry_date',
            'server_header',
            'dns_a_record',
            'dns_aaaa_record',
            'dns_spf',
            'dns_dkim',
            'dns_dmarc',
        ];
        foreach ($fieldsToFlatten as $key) {
            if (isset($scanResults[$key]) && is_array($scanResults[$key])) {
                $scanResults[$key] = implode(', ', $scanResults[$key]);
            }
        }

        // Use the actual protocol after redirects, as detected by the scanner
        $score = 200;
        // $score = WebsiteScoreBasic::calculateScore($scanResults,);
        $testos = WebsiteScoreBasic::calculateScore($scanResults,);

        return response()->json(["testos er" => $testos], 201);

        $createdSecurityTest = SecurityTestBasic::create([
            'website_id' => $website->id,
            'test_ran_at' => now(),
            'score' => $score,
            'https' => $scanResults['hasSSL'] ?? false,
            'website_prefix' => 'https',
            'tls_version' => $scanResults['tls_version'],
            'ssl_expiry_date' => $scanResults['ssl_expiry_date'],
            'has_csp' => $scanResults['has_csp'],
            'has_x_frame_options' => $scanResults['has_x_frame_options'],
            'has_hsts' => $scanResults['has_hsts'],
            'has_x_content_type_options' => $scanResults['has_x_content_type_options'],
            'server_header' => $scanResults['server_header'],
            'dns_a_record' => $scanResults['dns_a_record'],
            'dns_aaaa_record' => $scanResults['dns_aaaa_record'],
            'dns_spf' => $scanResults['dns_spf'],
            'dns_dkim' => $scanResults['dns_dkim'],
            'dns_dmarc' => $scanResults['dns_dmarc'],

            'first_name' => $first_name,
            'last_name' => $last_name,
            'email' => $email,
            'speed_ms' => $scanResults['speedMs'],
        ]);

        $createdSecurityTest->load('website');
        // Add speed_ms to the response (even if not saved in DB yet)
        $response = $createdSecurityTest->toArray();

        return response()->json($response, 201);
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

        return response()->json($securityTestBasic);
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
