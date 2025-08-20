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
        $url = $request->input('url');

        // Remove 'www.' from the beginning of a URL string if present.
        $slug = UrlHelper::removeWww($request->input('url'));

        //  Returns the scheme ('http' or 'https') of a URL, or null if not present.
        $scheme = UrlHelper::getScheme($request->input('url'));

        // Normalizes a URL by converting to lowercase, removing the scheme (http/https),
        //  removing 'www.' if present, and trimming any trailing slash.
        $normalizedUrl = UrlHelper::normalizeUrl($request->input('url'));

        // Create or find the website
        $website = ScannedWebsiteBasic::firstOrCreate(
            ['url' => $url],
            ['slug' => $slug],
        );

        return response()->json(['result' => $website]);
        // return response()->json(['normalizedUrl' => $normalizedUrl, 'scheme' => $scheme]);

        $test = SecurityTestBasic::create($request->validated());

        return response()->json($test, 201);
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
