# SecureVault - Enterprise Document Security Platform

## Tech stack

**Backend:** FastAPI, PostgreSQL, MinIO (S3-compatible storage), Elasticsearch  
**Frontend:** React + TypeScript  
**Infrastructure:** Docker Compose

## Security stuff I implemented

- **JWT authentication** - Tokens expire after 15 minutes, proper validation
- **AES-256-GCM encryption** - Each document gets its own encryption key
- **Brute force protection** - Account locks after 5 failed logins
- **Audit logging** - Everything gets logged to Elasticsearch with timestamps
- **SHA-256 checksums** - File integrity verification
- **RBAC** - Role-based permissions (though it's just me using it)
- **Security headers** - XSS protection, CSP, HSTS, etc.

## Running it

```bash
docker-compose up -d
```

Then go to http://localhost:3000

The database, storage, and logging all persist in Docker volumes so your data sticks around.

**Demo credentials:**
```
Email: demo@securevault.io
Password: Demo123!
```

## How encryption works

When you upload a file:
1. Generate a random 256-bit key for this specific document
2. Encrypt the file with AES-256-GCM using that key
3. Store the encrypted file in MinIO
4. Save the encryption key in the database (would use AWS KMS in production)
5. Calculate SHA-256 checksum for integrity verification

When you download:
1. Fetch the encryption key from the database
2. Download encrypted file from MinIO
3. Decrypt with the key
4. Verify checksum matches

## Known limitations

- Encryption keys are stored in PostgreSQL instead of a proper HSM/KMS
- No real user registration flow (just the demo account)
- File size limit is whatever MinIO allows by default
- Audit logs don't have retention policies set up
- No email notifications for security alerts

---

*Note: This README is still a work in progress.*
