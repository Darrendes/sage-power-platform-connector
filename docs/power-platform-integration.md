# Power Platform custom connector — integration notes

This document outlines a deployment-neutral integration approach. No tenant URLs, credentials, connector exports, or company configuration are included.

## API surface (high-level)

The prototype groups endpoints around:
- authentication and current-user information;
- user administration;
- article and stock lookups;
- customer receivables and accounting history;
- low-stock and credit-exposure alerts;
- dashboard indicators;
- synchronization timestamp and data retrieval.

Consult the endpoint attributes in `Program.cs` and confirm the required roles before exposing any route in a custom connector.

## Custom connector checklist

1. Use a test deployment with synthetic data and HTTPS.
2. Create the connector from the OpenAPI definition or configure actions manually.
3. Set the API host/base URL to the test environment.
4. Configure the approved authentication method; do not put a JWT signing secret in the connector definition.
5. Define request and response schemas, descriptions, and error responses.
6. Apply connector/DLP policies and restrict sharing to authorized users.
7. Test unauthorized requests, expired tokens, invalid parameters, and unavailable API/database scenarios.
8. Verify that returned data is limited to what each app user needs.

## Before any production use

The code requires a full review for endpoint-level authorization, SQL account permissions, CORS, token lifecycle, input validation, logging, rate limiting, error handling, privacy and data retention. The example login flow and claims model should be assessed against the organization's identity and access management requirements.
