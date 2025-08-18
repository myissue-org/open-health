<?php

namespace Database\Seeders;

use App\Models\Team;
use App\Models\User;
// use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        User::factory()->create([
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
        ]);

        Team::factory()->create([
            'user_id'          => 1,
            'name'             => 'MyISSUE',
            'address'          => null,
            'contact_page_url' => 'https://myissue.dk',
            'slug'             => 'myissue',
            'content'          => NULL,
            'public'           => true,
            'personal_team'    => false,
        ]);
    }
}
