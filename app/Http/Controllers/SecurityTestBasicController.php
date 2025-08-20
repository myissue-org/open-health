<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreSecurityTestBasicRequest;
use App\Http\Requests\UpdateSecurityTestBasicRequest;
use App\Models\ScannedWebsiteBasic;
use App\Models\SecurityTestBasic;
use App\Helpers\UrlHelper;

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

        // Remove 'www.' from the beginning of a URL string if present.
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

        $createdSecurityTest = SecurityTestBasic::create([
            'website_id' => $website->id,
            'test_ran_at' => now(),
            'score' => 0,
            'https' => $scheme === 'https',
            'website_prefix' => $scheme ?? 'http',
            'tls_version' => 'TLS 1.3', // fake data
            'ssl_expiry_date' => now()->addYear()->toDateString(), // fake data
            'has_csp' => false,
            'has_x_frame_options' => false,
            'has_hsts' => false,
            'has_x_content_type_options' => false,
            'server_header' => 'nginx/1.23.0', // fake data
            'dns_a_record' => false,
            'dns_aaaa_record' => false,
            'dns_spf' => false,
            'dns_dkim' => false,
            'dns_dmarc' => false,
            'first_name' => $first_name,
            'last_name' => $last_name,
            'email' => $email,
        ]);

        $createdSecurityTest->load('website');
        return response()->json($createdSecurityTest, 201);
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
