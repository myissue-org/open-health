<?php

use App\Http\Controllers\SecurityTestBasicController;
use Illuminate\Support\Facades\Route;



/*
|--------------------------------------------------------------------------
| Security Test Basics API Routes
|--------------------------------------------------------------------------
|
| Base URL: http://localhost:11500/api/security-test-basics
|
| Available Endpoints:
|   GET     /api/security-test-basics          -> List all records
|   GET     /api/security-test-basics/{id}     -> Get a single record
|   POST    /api/security-test-basics          -> Create a new record
|   PUT     /api/security-test-basics/{id}     -> Update a record
|   PATCH   /api/security-test-basics/{id}     -> Update a record partially
|   DELETE  /api/security-test-basics/{id}     -> Delete a record
|
| Notes:
| - Set Content-Type to 'application/json' in Postman.
| - For POST/PUT/PATCH requests, include JSON body with model fields.
| - Middleware is empty for now; authentication can be added later.
|
*/

Route::middleware([])->group(function () {
    Route::apiResource('security-test-basics', SecurityTestBasicController::class);
});
