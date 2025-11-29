# Anti DDoS Plugin

**Version:** 1.0.0  
**Author:** FlowAxy  
**Developer:** iTeffa (iteffa@flowaxy.com)  
**Studio:** FlowAxy  
**Website:** https://flowaxy.com  
**License:** Proprietary

## Description

Anti DDoS plugin for Flowaxy CMS provides protection against DDoS (Distributed Denial of Service) attacks by limiting requests from IP addresses and blocking suspicious activity. The plugin tracks request rates and automatically blocks IPs that exceed configured limits.

## Features

### Core Features

- 🛡️ **Rate Limiting** — Limits requests per minute and hour from each IP
- 🚫 **Automatic Blocking** — Blocks IPs that exceed rate limits with 429 Too Many Requests response
- ✅ **Whitelist Management** — Configure IPs that should never be blocked
- 🚨 **Blacklist Management** — Configure IPs that should always be blocked
- 📊 **Statistics** — View blocking statistics and top blocked IPs
- 📝 **Logging** — All blocked requests are logged to the database
- ⚙️ **Settings Page** — Easy configuration through admin panel
- 🔒 **Protected Admin Panel** — Admin panel and API are always accessible

### Technical Capabilities

- Early request interception via `handle_early_request` hook
- Request rate tracking by IP address
- Database-backed settings and logging
- Integration with Flowaxy CMS access control system
- Configurable block duration

## Requirements

- PHP >= 8.4.0
- Flowaxy CMS with plugin support
- MySQL/MariaDB database
- Admin access for configuration

## Installation

1. Copy the plugin directory to `plugins/anti-ddos/`.
2. Activate the plugin via the admin panel (Settings → Plugins).
3. The plugin will automatically create necessary database tables.

The plugin will automatically register its route and menu item upon activation.

## Usage

### Accessing the Settings Page

1. Log in to the admin panel.
2. Navigate to **System → Anti DDoS** in the menu.
3. Or go directly to `/admin/anti-ddos`.

### Configuration

#### Enable/Disable Protection

- Toggle the "Enable DDoS Protection" switch to enable or disable DDoS protection.

#### Rate Limits

Configure the maximum number of requests:
- **Max Requests Per Minute** — Maximum number of requests allowed per minute from a single IP (default: 60)
- **Max Requests Per Hour** — Maximum number of requests allowed per hour from a single IP (default: 1000)
- **Block Duration** — How long to block an IP after exceeding limits (default: 60 minutes)

#### IP Lists

**Whitelist IPs** — IPs that will never be blocked (one per line):
```
127.0.0.1
::1
192.168.1.100
```

**Blacklist IPs** — IPs that will always be blocked (one per line):
```
192.168.1.200
10.0.0.50
```

### How It Works

1. **Request Tracking** — The system tracks the number of requests from each IP address in the database.

2. **Rate Checking** — On each request, the system checks:
   - Number of requests in the last minute
   - Number of requests in the last hour
   - Whether the IP is in the whitelist (allowed) or blacklist (blocked)

3. **Blocking** — If limits are exceeded:
   - IP is logged to the `anti_ddos_logs` table
   - Request receives a 429 Too Many Requests response
   - IP remains blocked for the configured period

4. **Statistics** — All blocking activity is tracked for monitoring and analysis.

### Statistics

The plugin provides:
- **Blocked Today** — Number of IPs blocked today
- **Total Blocked** — Total number of blocked requests
- **Top Blocked IPs** — IP addresses with the most blocked attempts

## Plugin Structure

```
anti-ddos/
├── assets/
│   └── styles/
│       └── anti-ddos.css    # Styles for the settings page
├── src/
│   ├── admin/
│   │   └── pages/
│   │       └── AntiDdosAdminPage.php  # Admin settings page
│   └── Services/
│       └── AntiDdosService.php        # Core protection service
├── templates/
│   └── anti-ddos.php                  # Settings page template
├── tests/
│   └── AntiDdosPluginTest.php         # Diagnostic tests
├── init.php                             # Plugin initialization
├── plugin.json                          # Plugin metadata
└── README.md                            # Documentation
```

## Technical Details

### Architecture

The plugin uses a service-oriented architecture:

- **AntiDdosService** — Core service for rate limiting and IP blocking
- **AntiDdosAdminPage** — Admin panel page for configuration
- **Templates** — PHP templates for HTML rendering

### Database Tables

#### `anti_ddos_logs`

Logs all blocked requests:
- `id` — Unique identifier
- `ip_address` — IP address of blocked request
- `url` — Requested URL
- `blocked_at` — Block timestamp
- `created_at` — Creation timestamp

#### `anti_ddos_requests`

Tracks request rate by IP:
- `id` — Unique identifier
- `ip_address` — IP address
- `request_count` — Number of requests
- `first_request_at` — Time of first request
- `last_request_at` — Time of last request

### Security

- ✅ CSRF protection for all write operations
- ✅ Access permission checks before executing operations
- ✅ Admin panel and API are always accessible
- ✅ SQL injection protection via prepared statements
- ✅ XSS protection via output sanitization

### Hooks

The plugin uses the following hooks:

- `handle_early_request` (priority: 2) — Early request interception for rate limiting
- `admin_register_routes` — Register admin route
- `admin_menu` — Add menu item

## Configuration

### Default Behavior

By default, the plugin:
- Limits to 60 requests per minute per IP
- Limits to 1000 requests per hour per IP
- Blocks IPs for 60 minutes after exceeding limits
- Allows access to admin panel and API
- Logs all blocked requests

### Customization

You can customize protection:

1. By changing rate limits in the admin panel
2. By adding IPs to whitelist or blacklist
3. By modifying block duration
4. By adjusting rate checking logic in `AntiDdosService::checkRequestRate()`

## Development

### Dependencies

The plugin uses the following components from the Engine:

- `engine/core/support/base/BasePlugin.php`
- `engine/core/support/helpers/DatabaseHelper.php`
- `engine/interface/admin-ui/includes/AdminPage.php`
- `engine/core/support/helpers/UrlHelper.php`
- `engine/core/support/helpers/SecurityHelper.php`

### Extending Functionality

To extend the plugin:

1. **Configure rate limits** — Modify default values in the `install()` method
2. **Add new rate limits** — Extend the `checkRequestRate()` method
3. **Add new statistics** — Extend the `getStats()` method
4. **Customize UI** — Edit `templates/anti-ddos.php` and `assets/styles/anti-ddos.css`

## Support

If you find a bug or have questions:

1. Check log files for errors
2. Verify database tables are created
3. Ensure PHP has proper permissions

## Testing

### Diagnostic Tests

The plugin includes a set of diagnostic tests to verify functionality. Tests are located in the `tests/` directory:

- **AntiDdosPluginTest.php** — Set of automatic tests to verify:
  - Blocking IPs from blacklist
  - Allowing IPs from whitelist
  - Rate limiting (per minute and hour)
  - Saving and retrieving settings
  - Statistics and log clearing

Tests are automatically loaded through Flowaxy CMS `TestService` and `TestRunner` system.

### Quick Protection Test

You can test rate limiting using `curl`:

```bash
# Make multiple rapid requests
for i in {1..100}; do
    curl http://your-domain.com/
    sleep 0.1
done

# After exceeding the limit, you should receive 429 Too Many Requests
```

## License

Proprietary. All rights reserved.

## Version History

### 1.0.0 (2025-11-29)

- ✨ Initial release
- ✅ Rate limiting (per minute and hour)
- ✅ IP blocking and logging
- ✅ Admin panel settings page
- ✅ Statistics and monitoring
- ✅ Whitelist and blacklist management
- ✅ Integration with Flowaxy CMS Engine
- ✅ Database timezone support
- ✅ Diagnostic tests

## Author

**FlowAxy**  
Developer: iTeffa  
Email: iteffa@flowaxy.com  
Studio: flowaxy.com  
Website: https://flowaxy.com

---

*Developed with ❤️ for Flowaxy CMS*