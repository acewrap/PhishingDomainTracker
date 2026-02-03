# Installation & Deployment

## Prerequisites
- Python 3.8+
- SQLite (default) or PostgreSQL (recommended for production).

## Setup
1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set environment variables:
   - `FLASK_APP`: `app.app`
   - `SECRET_KEY`: A strong random string.
   - `DATABASE_URI`: (Optional) Database connection string. Defaults to `sqlite:///domains.db`.
     - For PostgreSQL: `postgresql://user:password@localhost/dbname`
   - `WHOISXML_API_KEY`: (Optional) API key for WhoisXML domain enrichment.
   - `URLSCAN_API_KEY`: (Optional) API key for Urlscan.io enrichment.
   - `PHISHTANK_API_KEY`: (Optional) API key for PhishTank integration.
   - `URLHAUS_API_KEY`: (Optional) API key for URLhaus submission.
   - `GOOGLE_WEBRISK_KEY`: (Optional) API key for Google Web Risk.
   - `GOOGLE_PROJECT_ID`: (Optional) Google Cloud Project ID for Web Risk submission.

## Database Initialization
Run the following commands to set up the database:
```bash
flask db upgrade
```

## Creating Admin User
The application does not create a default user automatically on startup for security reasons, but you can seed it using the flask shell or custom script.
*Example:*
```bash
export FLASK_APP=app/app.py
flask shell
>>> from app.extensions import db, bcrypt
>>> from app.models import User
>>> hashed = bcrypt.generate_password_hash('admin').decode('utf-8')
>>> u = User(username='admin', password_hash=hashed, password_expired=True)
>>> db.session.add(u)
>>> db.session.commit()
```
*(Note: I have already performed this step in the current environment).*

## Running the Server (Development)
```bash
flask run --host=0.0.0.0
```

## Running the Server (Production)
Use Gunicorn with the provided configuration file for a robust production setup.

```bash
gunicorn -c gunicorn_config.py wsgi:app
```

### Running the Scheduler
In production, run the background scheduler as a separate process to ensure consistent domain monitoring.

```bash
export FLASK_APP=app.app
flask run-scheduler
```

## Security Notes
- Ensure `FLASK_ENV` is set to `production` in a live environment to enable secure cookie settings (`Secure` flag).
- The application uses `ProxyFix` to handle `X-Forwarded-*` headers from Nginx. Ensure your Nginx configuration passes these headers correctly.

## Deployment on OpenShift

This section outlines the steps to deploy the application in a high-security OpenShift environment using the provided manifests.

### 1. Build and Push the Image
Use the provided `Dockerfile` to build the application image. The Dockerfile is hardened for security (non-root user, minimal footprint).

### 2. Apply Security Manifests
Apply the ServiceAccount and NetworkPolicy configurations:
```bash
oc apply -f openshift/serviceaccount.yaml
oc apply -f openshift/networkpolicy.yaml
```

### 3. ImageStream and Builds
The `openshift/imagestream.yaml` defines an ImageStream that tracks your private registry.
```bash
oc apply -f openshift/imagestream.yaml
```

### 4. Service CA Certificates
For corporate SSL inspection and private registry support, the application expects the Service CA bundle to be mounted at `/certs/ca-bundle.crt`.
Ensure your Deployment configures the volume mount:

```yaml
volumes:
  - name: service-ca
    configMap:
      name: <service-ca-configmap-name>
      items:
        - key: service-ca.crt
          path: ca-bundle.crt
volumeMounts:
  - name: service-ca
    mountPath: /certs
    readOnly: true
```

### 5. Image Pull Secrets
Ensure your ServiceAccount has the necessary credentials to pull from your private registry:

```bash
oc secrets link phishing-tracker-sa <your-pull-secret-name> --for=pull
```
