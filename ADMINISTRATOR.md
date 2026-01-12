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
