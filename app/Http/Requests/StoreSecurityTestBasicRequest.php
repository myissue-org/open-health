<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rules\Boolean;
use Illuminate\Validation\Rule;



class StoreSecurityTestBasicRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'website_id' => ['required', Rule::exists('scanned_website_basics', 'id')],
            'score' => ['nullable', 'integer'],
            'https' => ['nullable', 'boolean'],
            'website_prefix' => ['nullable', 'string'],
            'tls_version' => ['nullable', 'string'],
            'ssl_expiry_date' => ['nullable', 'date_format:Y-m-d H:i:s'],
            'has_csp' => ['nullable', 'boolean'],
            'has_x_frame_options' => ['nullable', 'boolean'],
            'has_hsts' => ['nullable', 'boolean'],
            'has_x_content_type_options' => ['nullable', 'boolean'],
            'server_header' => ['nullable', 'string'],
            'dns_a_record' => ['nullable', 'boolean'],
            'dns_aaaa_record' => ['nullable', 'boolean'],
            'dns_spf' => ['nullable', 'boolean'],
            'dns_dkim' => ['nullable', 'boolean'],
            'dns_dmarc' => ['nullable', 'boolean'],
        ];
    }
}
