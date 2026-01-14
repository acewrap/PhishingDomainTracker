# API Documentation

The application provides a RESTful API for programmatic access. All endpoints are prefixed with `/api/v1`.

## Authentication
Authentication is performed via HTTP Headers. You must include both:
- `X-API-Key`: Your public access key.
- `X-API-Secret`: Your private secret key.

These credentials can be managed in your User Profile.

## Endpoints

### GET /api/v1/domains
Retrieve a list of all tracked domains.

**Response:**
```json
[
  {
    "id": 1,
    "domain_name": "example-phish.com",
    "threat_status": "Red",
    "date_entered": "2023-10-27T10:00:00",
    "is_active": true,
    "has_login_page": true
  }
]
```

### POST /api/v1/domains
Add a new domain to track.

**Request Body:**
```json
{
  "domain_name": "suspicious-site.com"
}
```

**Response:**
- `201 Created`: Domain added successfully.
- `200 OK`: Domain already exists.
- `400 Bad Request`: Missing `domain_name`.

### GET /api/v1/backup
**Admin Only.** Retrieve a full database backup in JSON format.

**Response:**
- `200 OK`: JSON file containing Users, API Keys, and Domains.
- `403 Forbidden`: API Key does not belong to an admin.

### POST /api/v1/restore
**Admin Only.** Restore the database from a backup file.
**WARNING:** This acts as a full reset. Existing data will be wiped.

**Request Body:**
The JSON backup data obtained from `GET /api/v1/backup`.

**Response:**
- `200 OK`: Database restored successfully.
- `400 Bad Request`: Invalid JSON or corrupt backup file.
- `403 Forbidden`: API Key does not belong to an admin.
