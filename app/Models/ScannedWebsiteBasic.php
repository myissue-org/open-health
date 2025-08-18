<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ScannedWebsiteBasic extends Model
{
    /** @use HasFactory<\Database\Factories\ScannedWebsiteBasicFactory> */
    use HasFactory;

    // Only allow these fields from frontend
    protected $fillable = [
        'name',
        'url',
        'description',
        'created_by', // example
    ];

    // Relation to SecurityTestBasic
    public function securityTests()
    {
        return $this->hasMany(SecurityTestBasic::class, 'website_id');
    }
}
