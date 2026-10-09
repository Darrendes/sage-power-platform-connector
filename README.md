# ERP API Integration for Power Platform — Portfolio Case Study

> **Portfolio/demo project. Not production-ready.** This repository is a sanitized technical case study showing how a .NET Web API can expose ERP-style data to a Power Platform custom connector. It is not an official Sage product or an endorsed integration.

## Overview

This ASP.NET Core Minimal API prototype demonstrates an integration layer between an ERP database and a client such as Power Apps through HTTP endpoints. The code illustrates:

- JWT bearer authentication and role-based authorization
- Password hash verification with BCrypt
- SQL Server access through parameterized queries
- Article, stock, depot and customer-account queries
- Stock and receivables alerts
- Dashboard KPIs and synchronization endpoints
- OpenAPI/Swagger documentation for API exploration

The source originally depended on a local SQL Server and an organization-specific database. Those local connection details and hard-coded signing key have been removed from this portfolio copy.

## Technology stack

- C# / ASP.NET Core Minimal API
- SQL Server / `Microsoft.Data.SqlClient`
- JWT Bearer authentication
- BCrypt password hashing
- Swagger / OpenAPI
- Microsoft Power Platform custom connector (integration target)

## Repository structure

```text
.
├── Program.cs
├── Sage.csproj
├── Sage.sln
├── appsettings.json
├── appsettings.Development.json
├── Properties/
│   └── launchSettings.json
├── docs/
│   └── power-platform-integration.md
├── .gitignore
└── README.md
```

## Configuration

**Never commit credentials, real connection strings, signing keys, exported ERP data, or customer information.** Configuration is provided through environment variables.

PowerShell example (use only a local test database):

```powershell
$env:ConnectionStrings__SageDatabase = "Server=localhost;Database=ERP_DEMO;Integrated Security=True;TrustServerCertificate=True"
$env:Jwt__Key = "<generate-a-random-secret-of-at-least-32-bytes>"
dotnet restore
dotnet run
```

Generate a random secret locally; do not reuse a production or company key. For example, PowerShell can generate one with:

```powershell
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:Jwt__Key = [Convert]::ToBase64String($bytes)
```

The connection string must point to a test database with the expected schema. This repository does not include a database backup or real ERP data. Some endpoints require ERP tables and columns that are not available in a clean SQL Server installation.

For browser-based clients, configure `Cors:AllowedOrigins` with the exact trusted origins in the local configuration. Do not use a wildcard origin in a production deployment.

## Running locally

Prerequisites:
- A compatible .NET SDK for the target framework in `AngeSage.csproj`
- SQL Server test instance
- A test database with the expected schema
- A JWT signing key supplied through environment configuration

Then run:

```powershell
dotnet restore
dotnet run
```

Open the local Swagger URL printed by the application and test only with synthetic data. This project has not been represented as a fully verified production build.

## Security notes and limitations

This is a learning/portfolio codebase and must be reviewed before any real deployment.

- Provision user accounts through a controlled administrative process; a public bootstrap endpoint with default credentials has intentionally been removed.
- Use a least-privilege SQL Server account rather than a privileged database account.
- Review authorization on every endpoint and apply least privilege to each role.
- Restrict CORS to known client origins; an empty allow-list does not authorize arbitrary browser origins.
- Add rate limiting, structured security logging, request validation, exception handling and monitoring before deployment.
- Review data minimization: customer names, phone numbers, balances, accounting entries and stock levels may be confidential.
- Use HTTPS and manage signing keys through a secret manager in deployed environments.
- Validate the SQL queries, business rules and ERP schema against a synthetic test database before relying on their outputs.

## Suggested Power Platform flow

1. Host the API in a controlled environment reachable by the Power Platform tenant.
2. Define the API base URL and authentication scheme in a custom connector.
3. Import the OpenAPI definition from the API's Swagger endpoint where supported.
4. Map selected endpoints to Power Apps actions.
5. Test using synthetic records and a dedicated least-privilege identity.
6. Document refresh/synchronization limits and failure handling.

The actual connector definition, tenant configuration and production deployment are environment-specific and are not included in this repository.

## Disclaimer

Sage is a trademark of its respective owner. This is an independent integration case study; it is not affiliated with or endorsed by Sage. All example names and sample concepts are illustrative. Do not use this repository to connect to a live company database without authorization and a security review.
