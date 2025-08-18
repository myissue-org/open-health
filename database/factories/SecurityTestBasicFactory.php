<?php

namespace Database\Factories;

use App\Models\ScannedWebsiteBasic;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\SecurityTestBasic>
 */
class SecurityTestBasicFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'website_id' => ScannedWebsiteBasic::factory(), // create a related website automatically
            'test_ran_at' => $this->faker->dateTimeBetween('-1 year', 'now'),
            'score' => $this->faker->numberBetween(0, 100),

            // Core checks
            'https' => $this->faker->boolean(80), // 80% chance true
            'website_prefix' => $this->faker->randomElement(['http', 'https']),

            'tls_version' => $this->faker->randomElement(['TLS 1.2', 'TLS 1.3', null]),
            'ssl_expiry_date' => $this->faker->dateTimeBetween('now', '+2 years'),

            // Security headers
            'has_csp' => $this->faker->boolean(70),
            'has_x_frame_options' => $this->faker->boolean(70),
            'has_hsts' => $this->faker->boolean(70),
            'has_x_content_type_options' => $this->faker->boolean(70),

            // Server info
            'server_header' => $this->faker->randomElement(['nginx', 'Apache', 'LiteSpeed', null]),

            // DNS records
            'dns_a_record' => $this->faker->boolean(90),
            'dns_aaaa_record' => $this->faker->boolean(70),
            'dns_spf' => $this->faker->boolean(80),
            'dns_dkim' => $this->faker->boolean(80),
            'dns_dmarc' => $this->faker->boolean(80),
        ];
    }
}
