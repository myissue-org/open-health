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
            'url' => ['required', 'string', 'min:2', 'max:255'],
            'title' => ['nullable', 'string', 'min:2', 'max:255'],
            'first_name' => ['nullable', 'string', 'min:2', 'max:255'],
            'last_name' => ['nullable', 'string', 'min:2', 'max:255'],
            'email' => ['required', 'string', 'email', 'min:2', 'max:255'],
        ];
    }

    /**
     * Add custom validation after default rules.
     */
    public function withValidator($validator)
    {
        $validator->after(function ($validator) {
            $url = $this->input('url');
            if ($url && !preg_match('#^https?://#i', $url)) {
                $validator->errors()->add('url', 'The url must start with http:// or https://');
            }
            if ($url && !preg_match('/\./', $url)) {
                $validator->errors()->add('url', 'The url must contain a dot (.) and be a valid domain.');
            }
        });
    }
}
