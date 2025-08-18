<?php

namespace Database\Factories;

use App\Models\Team;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;


/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\ScannedWebsiteBasic>
 */
class ScannedWebsiteBasicFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'team_id' => Team::inRandomOrder()->first()?->id,
            'user_id' => User::inRandomOrder()->first()?->id,
            'url'     => $this->faker->domainName,
            'slug'    => Str::slug($this->faker->unique()->domainName),
            'title'   => $this->faker->sentence(3),
            'public'  => $this->faker->boolean(70),
        ];
    }
}
