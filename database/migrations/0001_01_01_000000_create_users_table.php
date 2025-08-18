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
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('email')->unique();
            $table->timestamp('email_verified_at')->nullable();
            $table->string('password');

            $table->string("first_name");
            $table->string("last_name");
            $table->string("country")->nullable();
            $table->string("city")->nullable();
            $table->string("state")->nullable();

            $table->string("line1")->nullable();
            $table->string("line2")->nullable();

            $table->string("postal_code")->nullable();
            $table->string("phone_code")->nullable();

            $table->string("vat_id")->nullable();
            $table->string("tax_id")->nullable();
            $table->string("vat_number")->nullable();

            $table->string("phone")->nullable();
            $table->string("job_title")->nullable();

            $table->string("username")->unique()->index();

            $table->longText("content")->nullable();
            $table->boolean("public")->nullable();

            $table->foreignId("current_team_id")->nullable();

            $table->rememberToken();
            $table->timestamps();
        });

        Schema::create('password_reset_tokens', function (Blueprint $table) {
            $table->string('email')->primary();
            $table->string('token');
            $table->timestamp('created_at')->nullable();
        });

        Schema::create('sessions', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->foreignId('user_id')->nullable()->index();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->longText('payload');
            $table->integer('last_activity')->index();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('users');
        Schema::dropIfExists('password_reset_tokens');
        Schema::dropIfExists('sessions');
    }
};
