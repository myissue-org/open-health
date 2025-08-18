<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\User>
 */
class UserFactory extends Factory
{
    /**
     * The current password being used by the factory.
     */
    protected static ?string $password;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'first_name'       => 'Qais',
            'last_name'        => 'Wardag',
            'email'            => 'qw@myissue.dk',
            'password'         => '123456',
            'country'          => 'Denmark',
            'city'             => 'Copenhagen',
            'state'            => null,
            'line1'            => null,
            'line2'            => null,
            'postal_code'      => null,
            'phone_code'       => null,
            'vat_id'           => null,
            'tax_id'           => null,
            'vat_number'       => null,
            'phone'            => null,
            'job_title'        => null,
            'username'         => 'qaiswardag',
            'content'          => null,
            'public'           => true,
            'email_verified_at' => now(),
            'current_team_id'  => 1,
        ];
    }

    /**
     * Indicate that the model's email address should be unverified.
     */
    public function unverified(): static
    {
        return $this->state(fn(array $attributes) => [
            'email_verified_at' => null,
        ]);
    }
}
