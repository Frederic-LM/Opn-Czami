# Op'n-Czami Server-Side Components

**License: MIT**

This folder contains the **open-source server-side files** that Op'n-Czami deploys to your web server. These files enable analytics logging and certificate serving.

## Philosophy

These server-side components are intentionally **open-source and separated from the closed-source Python application** for several reasons:

1. **Trust & Transparency**: You can inspect exactly what code runs on your server
2. **Security Auditing**: Community review and vulnerability reporting
3. **Customization**: Adapt the scripts to your specific infrastructure
4. **Portability**: Use different server software (Apache, Nginx, etc.)


## Folder Structure

```
server_side/
├── LICENSE                      # MIT License for all server-side code
├── README.md                    # This file
├── apache/                      # Apache-specific files
│   ├── .htaccess               # URL rewriting & security rules
│   └── analytics.php           # Event logging & file serving
└── nginx/                       # Nginx configuration examples
    └── nginx.conf.example      # Reference configuration for Nginx users
```

## Files Overview

### Apache Setup

#### `.htaccess`
- **Purpose**: Apache configuration for URL rewriting and security
- **What it does**:
  - Protects `analytics.log` from direct public access
  - Routes extension-less URLs (e.g., `/certificate123`) through `analytics.php`
  - Optional: Enables compression and cache headers
- **Requirements**: Apache with `mod_rewrite` enabled

#### `analytics.php`
- **Purpose**: Logs certificate views and serves .lky files
- **What it does**:
  - Records visitor IP and timestamp when a certificate is accessed
  - Performs automatic monthly log rotation
  - Serves the requested certificate file
  - Uses thread-safe file locking for concurrent access
- **Requirements**:
  - PHP 7.0+
  - Write permissions for the directory
  - Functions enabled: `flock()`, `rename()`, `file_put_contents()`

### Nginx Setup

#### `nginx.conf.example`
- **Purpose**: Reference configuration for Nginx users
- **Why separate?**: Nginx doesn't use `.htaccess`; it requires server block configuration
- **Usage**: Copy relevant sections into your `/etc/nginx/sites-available/your-site` config

## Deployment

### Manual Deployment (Advanced Users)

1. **Copy the files to your server**:
   ```bash
   # For Apache users:
   scp server_side/apache/.htaccess user@your-server:/path/to/certificates/
   scp server_side/apache/analytics.php user@your-server:/path/to/certificates/

   # For Nginx users:
   # Copy the configuration from nginx.conf.example into your server config
   ```

2. **Set permissions**:
   ```bash
   chmod 755 /path/to/certificates
   chmod 644 /path/to/certificates/.htaccess
   chmod 644 /path/to/certificates/analytics.php

   # Make sure the web server user can write analytics.log
   chown www-data:www-data /path/to/certificates
   ```

3. **Verify setup** (see Verification section below)

### Automatic Deployment (Op'n-Czami Client)

The Op'n-Czami Python client can automatically deploy these files via FTP:

1. Configure FTP settings in the Settings tab
2. Click "Save Settings & Upload Public Files"
3. The client will deploy the appropriate `.htaccess` and `analytics.php` files

## Log File Format

The `analytics.log` file stores event records in this format:

```
YYYY-MM-DD HH:MM:SS | IP_ADDRESS | certificate_filename
```

Example:
```
2025-10-25 14:32:15 | 192.168.1.100 | certificate_abc123def456
2025-10-25 14:35:42 | 203.0.113.45 | certificate_xyz789
```

### Log Rotation

- **Frequency**: Monthly (first access after month boundary)
- **Current file**: `analytics.log` (current month)
- **Archives**: `analytics-2025-10.log`, `analytics-2025-09.log`, etc.

## Verification Checklist

After deployment, verify your setup:

### FTP Upload Check ✓
```bash
# Connect to FTP and verify files exist:
ls -la /path/to/certificates/ | grep -E "\.htaccess|analytics"
```

### PHP Execution Check ✓
```bash
# Test if PHP is running:
curl -I https://your-domain.com/analytics.php?file=nonexistent
# Should return: HTTP/1.1 404 Not Found
# If you see PHP source code, PHP is not executing
```

### URL Rewriting Check ✓
```bash
# Test URL rewriting (Apache/.htaccess only):
curl -I https://your-domain.com/test_certificate
# Should return: HTTP/1.1 404 File not found (from analytics.php)
# If rewriting isn't working: HTTP/1.1 404 Not Found (from Apache)
```

### Log Writing Check ✓
```bash
# After a certificate is accessed, check if analytics.log exists:
ls -la /path/to/certificates/analytics.log
# Should show the file with recent modification time
```

### Log Protection Check ✓
```bash
# Verify analytics.log is not publicly accessible:
curl -I https://your-domain.com/analytics.log
# Should return: HTTP/1.1 403 Forbidden
# If you can download it (200 OK), .htaccess is not working
```

## Customization Examples

### Example 1: Logging to MySQL Instead of File

Edit `analytics.php` to use MySQL:

```php
function append_analytics_event($ip, $filename) {
    // Instead of file logging, use MySQL:
    $mysqli = new mysqli("localhost", "user", "password", "analytics_db");
    $stmt = $mysqli->prepare("INSERT INTO events (ip, filename, timestamp) VALUES (?, ?, NOW())");
    $stmt->bind_param("ss", $ip, $filename);
    return $stmt->execute();
}
```

### Example 2: Custom Log Format

Modify the log line format in `analytics.php`:

```php
// Original:
$event = $timestamp . ' | ' . $ip . ' | ' . $filename . "\n";

// Custom (JSON):
$event = json_encode(['timestamp' => $timestamp, 'ip' => $ip, 'file' => $filename]) . "\n";
```

### Example 3: Filter Requests

Add logic to skip certain requests:

```php
// Skip internal IPs
if (preg_match('/^(127\.|192\.168\.|10\.)/', $ip)) {
    // Don't log internal access
} else {
    append_analytics_event($ip, $file);
}
```

## Server Requirements

| Requirement | Apache | Nginx |
|------------|--------|-------|
| **Web Server** | Apache 2.2+ | Nginx 1.10+ |
| **PHP Version** | 7.0+ | 7.0+ |
| **Modules** | mod_rewrite | None (built-in) |
| **File Permissions** | 755 directory, 644 files | 755 directory, 644 files |
| **Functions** | flock(), rename(), file_put_contents() | (same) |
| **Server OS** | Linux/Unix/Windows | Linux/Unix |

## Troubleshooting

### Analytics not being logged

1. **Check PHP execution**:
   ```bash
   curl -I https://your-domain.com/analytics.php?file=test
   ```
   Should NOT show PHP source code

2. **Check file permissions**:
   ```bash
   ls -la /path/to/certificates/
   # Directory should be 755, files 644
   # Owner should be www-data:www-data
   ```

3. **Check .htaccess** (Apache only):
   - Verify `mod_rewrite` is enabled: `apache2ctl -M | grep rewrite`
   - Verify `.htaccess` is in the right directory
   - Check Apache error log: `tail -f /var/log/apache2/error.log`

### analytics.log is publicly accessible

1. **Apache**: Verify `.htaccess` is deployed and contains the security rules
2. **Nginx**: Add the location block from `nginx.conf.example`
3. Check web server error logs for configuration issues

### URL rewriting not working (404 errors)

- **Apache**:
  - Verify `mod_rewrite` is enabled
  - Check that `.htaccess` is in the correct directory
  - Verify Apache allows `.htaccess` overrides: `AllowOverride All`

- **Nginx**:
  - Copy configuration from `nginx.conf.example`
  - Test: `sudo nginx -t`
  - Reload: `sudo systemctl reload nginx`

## Contributing

Found a bug or have a suggestion? Please open an issue on the Op'n-Czami GitHub repository.

## Security Considerations

1. **Keep files updated**: Check for security updates from Op'n-Czami
2. **Monitor logs**: Regularly review `analytics.log` for unusual patterns
3. **Verify integrity**: Use the hashes provided with each release
4. **Use HTTPS**: Always serve certificates over HTTPS
5. **Restrict access**: Consider IP whitelisting if possible

## Support

- **For Op'n-Czami client issues**: https://github.com/anthropics/claude-code (or your repo)
- **For Apache questions**: https://httpd.apache.org/docs/
- **For Nginx questions**: https://nginx.org/en/docs/
- **For PHP questions**: https://www.php.net/manual/

---

**License**: MIT - These files are open-source and free to use, modify, and distribute.
