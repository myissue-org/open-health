<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreSecurityTestBasicRequest;
use App\Http\Requests\UpdateSecurityTestBasicRequest;
use App\Models\SecurityTestBasic;

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
