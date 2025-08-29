<p align="center">
  <img width="200" style="max-width: 100%;" src="./public/logo.svg" alt="OpenHealth Logo" />
</p>

# OpenHealth

**OpenHealth** is an open-source Laravel API designed to scan websites for security vulnerabilities and provide a detailed report on their security health. By submitting a URL, users can receive a comprehensive analysis of potential risks, including checks for HTTPS, TLS versions, security headers, DNS configurations, and more. This tool helps developers, security professionals, and teams ensure their websites are safe, secure, and compliant with modern security standards.

Demo: [Play around](https://www.myissue.studio)

---

## Features

-   **Website Security Scanning**: Submit a URL to scan for vulnerabilities and receive a detailed security health report.
-   **Comprehensive Checks**: Evaluates multiple aspects of website security, including:
    -   HTTPS and TLS version validation
    -   Security headers (HSTS, CSP, X-Frame-Options, etc.)
    -   DNS configurations (SPF, DKIM, DMARC, DNSSEC, etc.)
    -   Cookie security (Secure, HttpOnly, SameSite attributes)
    -   Server and resource configurations
-   **API-Driven**: Easily integrate with other applications via a RESTful API.
-   **Detailed Reports**: Returns a security score (0-100) and specific recommendations for improving website security.
-   **Built with Laravel**: Leverages Laravel's robust framework for scalability and ease of maintenance.
-   **Open-Source**: Fully open-source, allowing contributions and custom extensions.

---

## Installation

To get started with OpenHealth, follow these steps:

1. **Clone the Repository**:

    ```bash
    git clone git@github.com:myissue-org/open-health.git
    cd open-health
    ```

2. **Install Dependencies**:

    ```bash
    composer install
    ```

3. **Configure Environment**:

    - Copy the `.env.example` file to `.env` and update it with your database and other configuration details.

    ```bash
    cp .env.example .env
    ```

4. **Generate Application Key**:

    ```bash
    php artisan key:generate
    ```

5. **Run Migrations**:

    ```bash
    php artisan migrate
    ```

6. **Start the Server**:
    ```bash
    php artisan serve
    ```

The API will be available at `http://localhost:8000` (or the port specified by Laravel).

---

## API Routes

OpenHealth provides a RESTful API for interacting with the security scanning functionality. Below are the available endpoints:

### Base URL

`http://localhost:8000/api/v1`

### Endpoints

| Method   | Endpoint                     | Description                             |
| -------- | ---------------------------- | --------------------------------------- |
| `GET`    | `/security-test-basics`      | List all security test records          |
| `GET`    | `/security-test-basics/{id}` | Retrieve a single security test record  |
| `POST`   | `/security-test-basics`      | Create a new security test record       |
| `PUT`    | `/security-test-basics/{id}` | Update a security test record           |
| `PATCH`  | `/security-test-basics/{id}` | Partially update a security test record |
| `DELETE` | `/security-test-basics/{id}` | Delete a security test record           |

### Usage Notes

-   **Content-Type**: Set to `application/json` for all requests.
-   **Request Body**: For `POST`, `PUT`, and `PATCH` requests, include a JSON body with the required fields (e.g., URL to scan).
-   **Authentication**: Currently, no middleware is applied. Authentication can be added as needed.

### Example Request

To scan a website, send a `POST` request to `/api/v1/security-test-basics`:

```bash
curl -X POST http://localhost:8000/api/v1/security-test-basics \
-H "Content-Type: application/json" \
-d '{"url": "https://example.com"}'
```

### Example Response

```json
{
  "id": 45,
  "url": "https://example.com",
  "score": 91,
  "status": "Minimal Risk",
  "checks": {
    "https": "Secure: Data is encrypted",
    "tls_version": "High Risk: Upgrade to TLS 1.2 or 1.3",
    "hsts": "Moderate Risk: Enable HSTS header",
    ...
  },
  "created_at": "2025-08-29T11:19:00Z"
}
```

---

## Contributing

Thank you for considering contributing to OpenHealth! To contribute:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/YourFeature`).
3. Commit your changes (`git commit -m 'Add YourFeature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a Pull Request.

Please ensure your code follows the project's coding standards and includes appropriate tests.

## Security Vulnerabilities

If you discover a security vulnerability within OpenHealth, please send an email to the maintainers at [security@myissue.studio](mailto:security@myissue.studio). We appreciate your help in keeping OpenHealth secure.

## License

OpenHealth is open-sourced software licensed under the [MIT License](https://opensource.org/licenses/MIT).
