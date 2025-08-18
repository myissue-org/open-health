<?php

namespace Database\Seeders;

use App\Models\ScannedWebsiteBasic;
use App\Models\SecurityTestBasic;
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
        User::factory(1)->create();

        Team::factory(1)->create();

        ScannedWebsiteBasic::factory(10)->create();
        SecurityTestBasic::factory(10)->create();
    }
}
