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

### POST /api/v1/evidence
Upload an email file (.eml or .msg) for analysis.

**Request:**
- `Content-Type`: `multipart/form-data`
- Body Parameter: `file` (The file to upload)

**Response:**
```json
{
  "message": "Evidence uploaded and processing started",
  "id": 15
}
```

### GET /api/v1/evidence/<id>
Retrieve report information about a submitted email extract.

**Response:**
```json
{
  "id": 15,
  "filename": "suspicious.eml",
  "submitted_at": "2023-10-28T14:30:00",
  "submitted_by": "analyst1",
  "extracted_indicators": {
      "urls": ["http://phishing.com/login"],
      "ips": ["1.2.3.4"],
      "domains": ["phishing.com"]
  },
  "analysis_report": {
      "vt_stats": {
          "phishing.com": {
               "malicious": 5,
               "harmless": 80
          }
      }
  },
  "correlations_count": 2
}
```

### GET /api/v1/backup
**Admin Only.** Retrieve a full database backup in JSON format.

**Response:**
- `200 OK`: JSON file containing Users, API Keys, Domains, Evidence, etc.
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
