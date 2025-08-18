<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Team extends Model
{
    /** @use HasFactory<\Database\Factories\TeamFactory> */
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     *
     * @var string<int, string>
     */
    protected $fillable = [
        "user_id",
        "name",
        "address",
        "contact_page_url",
        "slug",
        "personal_team",
        "public",
        "logo_original",
        "logo_thumbnail",
        "logo_medium",
        "logo_large",

        "monday_opening_time",
        "monday_closing_time",

        "tuesday_opening_time",
        "tuesday_closing_time",

        "wednesday_opening_time",
        "wednesday_closing_time",

        "thursday_opening_time",
        "thursday_closing_time",

        "friday_opening_time",
        "friday_closing_time",

        "saturday_opening_time",
        "saturday_closing_time",

        "sunday_opening_time",
        "sunday_closing_time",

        "time_zone",
    ];

    public function owner()
    {
        return $this->belongsTo(User::class, "user_id", "id");
    }
}
