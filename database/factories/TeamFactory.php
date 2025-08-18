<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\Team>
 */
class TeamFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'user_id'          => 1,
            'name'             => 'MyISSUE',
            'address'          => null,
            'contact_page_url' => 'https://myissue.dk',
            'slug'             => 'myissue',
            'content'          => NULL,
            'public'           => true,
            'personal_team'    => false,
        ];
    }
}
