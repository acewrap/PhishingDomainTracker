# Administrator Documentation

## Initial Setup
The application comes with an initial administrator account.
**Username:** `admin`
**Initial Password:** `admin` (You will be forced to change this upon first login).

## Creating Users
1. Log in as an administrator.
2. Click "Create User" in the navigation bar.
3. Enter a username and an initial password.
4. The user will be created, and an initial API Key pair (Access Key and Secret) will be generated.
   - **Note:** You must securely transmit the initial credentials to the user. The user will be forced to change their password upon first login.
   - **Note:** The API Secret is shown only once. If lost, the user can regenerate it from their profile.

## Domain Management
As an administrator (and user), you can:
- **Add Domains:** Manually add domains to track.
- **Enrich Domains:** Trigger enrichment (Whois, URLScan, etc.).
- **Update Status:** Manually set status (e.g., Whitelisted, Takedown Requested).
- **Delete Domains:** Remove domains from the system.
- **Reports:** Generate CSV reports based on date range and status.

## Advanced Data Management
These features are available in the **Admin** dropdown menu.

### Bulk Import
You can bulk import domains using a CSV file.
1. Navigate to **Admin > Import CSV**.
2. Upload a CSV file. The file must have a header row with at least a `domain` column. An optional `entered_date` (YYYY-MM-DD) column is also supported.
3. Duplicates will be automatically skipped.

### Database Backup & Restore
1. Navigate to **Admin > Backup/Restore**.
2. **Backup:** Click "Download Backup" to get a full JSON dump of Users, API Keys, and Domains.
3. **Restore:** Upload a previously generated backup JSON file.
   - **WARNING:** This will **delete all existing data** in the database and replace it with the backup content. This action cannot be undone.
