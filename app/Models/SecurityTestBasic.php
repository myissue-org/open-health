<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class SecurityTestBasic extends Model
{
    /** @use HasFactory<\Database\Factories\SecurityTestBasicFactory> */
    use HasFactory;

    // Only allow safe fields from frontend
    protected $fillable = [
        'score',
        'https',
        'tls_version',
        'ssl_expiry_date',
        'has_csp',
        'has_x_frame_options',
        'has_hsts',
        'has_x_content_type_options',
        'server_header',
        'dns_a_record',
        'dns_aaaa_record',
        'dns_spf',
        'dns_dkim',
        'dns_dmarc',
        'website_prefix',
        'test_ran_at',

        'first_name',
        'last_name',
        'email',
    ];

    // Relation back to website
    public function website()
    {
        return $this->belongsTo(ScannedWebsiteBasic::class, 'website_id');
    }
}
