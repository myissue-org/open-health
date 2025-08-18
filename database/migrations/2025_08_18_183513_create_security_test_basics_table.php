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
                ->constrained('scanned_website_basics') // link to the basic websites
                ->onDelete('cascade');

            $table->timestamp('test_ran_at')->useCurrent();

            // Overall score
            $table->unsignedTinyInteger('score')->default(0); // 0-100 or 0-5

            // Core checks
            $table->boolean('https')->default(false);
            $table->string('website_prefix')->nullable(); // 'http' or 'https'
            $table->string('tls_version')->nullable();
            $table->date('ssl_expiry_date')->nullable();

            // Security headers
            $table->boolean('has_csp')->default(false);
            $table->boolean('has_x_frame_options')->default(false);
            $table->boolean('has_hsts')->default(false);
            $table->boolean('has_x_content_type_options')->default(false);

            // Server info
            $table->string('server_header')->nullable();

            // DNS records
            $table->boolean('dns_a_record')->default(false);
            $table->boolean('dns_aaaa_record')->default(false);
            $table->boolean('dns_spf')->default(false);
            $table->boolean('dns_dkim')->default(false);
            $table->boolean('dns_dmarc')->default(false);


            $table->timestamps();
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
