<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('security_test_basics', function (Blueprint $table) {
            $table->id();
            $table->foreignId('website_id')
                ->constrained('scanned_website_basics')
                ->onDelete('cascade');
            $table->timestamp('test_ran_at')->useCurrent()->index();
            $table->unsignedTinyInteger('score')->default(0);

            // Core checks
            $table->boolean('https')->default(false);
            $table->string('website_prefix')->nullable();
            $table->string('tls_version')->nullable();
            $table->boolean('is_tls_outdated')->default(false);
            $table->date('ssl_expiry_date')->nullable();
            $table->boolean('is_ssl_expiring_soon')->default(false);
            $table->boolean('has_weak_ciphers')->default(false);

            // Security headers
            $table->boolean('has_csp')->default(false);
            $table->boolean('is_csp_weak')->default(false);
            $table->boolean('has_x_frame_options')->default(false);
            $table->boolean('has_hsts')->default(false);
            $table->boolean('is_hsts_preloaded')->default(false);
            $table->boolean('has_x_content_type_options')->default(false);
            $table->boolean('has_permissive_cors')->default(false);
            $table->boolean('has_secure_cookies')->default(true);
            $table->boolean('has_httponly_cookies')->default(true);
            $table->boolean('has_samesite_cookies')->default(true);

            // Server info
            $table->string('server_header')->nullable();
            $table->boolean('has_server_version_exposed')->default(false);

            // Website speed
            $table->unsignedInteger('speed_ms')->nullable();

            // DNS records
            $table->boolean('dns_a_record')->default(false);
            $table->boolean('dns_aaaa_record')->default(false);
            $table->boolean('dns_caa_record')->default(false);
            $table->boolean('dnssec_enabled')->default(false);
            $table->boolean('dns_spf')->default(false);
            $table->boolean('dns_dkim')->default(false);
            $table->boolean('dns_dmarc')->default(false);
            $table->boolean('is_dmarc_strong')->default(false);

            // Content checks
            $table->boolean('has_mixed_content')->default(false);
            $table->boolean('has_sri')->default(true);
            $table->boolean('has_http_redirect')->default(false);

            // Error handling
            $table->string('error')->nullable();

            // User info
            $table->string('first_name')->nullable();
            $table->string('last_name')->nullable();
            $table->string('email')->nullable();

            $table->timestamps();

            // Composite index for common queries
            $table->index(['website_id', 'test_ran_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('security_test_basics');
    }
};
