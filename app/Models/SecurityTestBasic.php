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
        'website_id',
        'test_ran_at',
        'score',
        'https',
        'website_prefix',
        'tls_version',
        'is_tls_outdated',
        'ssl_expiry_date',
        'is_ssl_expiring_soon',
        'has_weak_ciphers',
        'has_csp',
        'is_csp_weak',
        'has_x_frame_options',
        'has_hsts',
        'is_hsts_preloaded',
        'has_x_content_type_options',
        'has_permissive_cors',
        'has_secure_cookies',
        'has_httponly_cookies',
        'has_samesite_cookies',
        'server_header',
        'has_server_version_exposed',
        'speed_ms',
        'dns_a_record',
        'dns_aaaa_record',
        'dns_caa_record',
        'dnssec_enabled',
        'dns_spf',
        'dns_dkim',
        'dns_dmarc',
        'is_dmarc_strong',
        'has_mixed_content',
        'has_sri',
        'has_http_redirect',
        'error',
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
