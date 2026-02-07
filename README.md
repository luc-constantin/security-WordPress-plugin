# Accolades Guard

[![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-0073aa?logo=wordpress&logoColor=white)](https://wordpress.org)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-777bb4?logo=php&logoColor=white)](https://www.php.net)
[![License](https://img.shields.io/badge/License-GPLv2%2B-green)](LICENSE)

**Accolades Guard** is a lightweight WordPress hardening and integrity-monitoring plugin built for developers, freelancers, and site owners who want **real protection without bloat**.

It focuses on preventing common attack vectors, blocking spam at the source, and detecting unauthorized file changes — all while keeping the admin experience clean and fast.

---

## Screenshot

![Accolades Guard Dashboard](https://raw.githubusercontent.com/luc-constantin/security-WordPress-plugin/main/accolades-guard-dashboard.png)


---

## Why Accolades Guard?

Most security plugins try to do everything:
firewalls, scanners, dashboards, upsells, popups.

Accolades Guard does **only what matters**:

- Stops spam **before it hits the database**
- Disables dangerous or abused WordPress features
- Monitors file integrity with clear alerts
- Adds zero frontend scripts
- Adds no background services
- Adds no third-party dependencies

You stay in control.

---

## Features

### Comment & Pingback Protection
- Disable XML-RPC pingbacks and trackbacks
- Block public comment submissions entirely
- Optionally allow **admin-only comments**
- Prevent internal links from appearing as comments

### Hardening
- Block suspicious query strings used in malware redirects
- Disable Theme Editor and Plugin Editor safely
- Reduce attack surface without breaking updates

### Integrity Monitoring
- Create a file integrity baseline
- Monitor:
  - WordPress core
  - Core + plugins + themes
- Detect:
  - Added files
  - Removed files
  - Modified files
- Email alerts when changes are detected
- Manual “Run Check Now” option
- Configurable schedule:
  - Hourly
  - Daily (default)
  - Weekly
  - Custom intervals

### Developer Signature (Optional)
- Add a harmless HTML comment after the doctype
- Frontend only
- Useful for authorship or internal audits

---

## Designed For

- Freelance developers
- Agencies
- Long-lived WordPress sites
- Client websites
- Minimalist stacks
- People who already understand WordPress

If you want flashy dashboards and AI buzzwords, this is not for you.

If you want **clarity, control, and silence**, it is.

---

## Installation

1. Download or clone this repository
2. Upload the folder to `/wp-content/plugins/`
3. Activate **Accolades Guard** from the Plugins screen
4. Open **Accolades Guard** from the admin sidebar
5. Create a baseline
6. Adjust controls as needed

---

## How Integrity Monitoring Works

1. A baseline of file hashes is created
2. On each scheduled run, files are re-hashed
3. Any difference triggers:
   - Admin notice
   - Email alert
4. You decide:
   - Recreate baseline after updates
   - Investigate unexpected changes

No remote scanning.
No data leaves your server.

---

## Performance

- No frontend JS or CSS
- No cron overload
- No external API calls
- No database growth from spam

Runs only when needed.

---

## Roadmap (Intentional & Small)

- Export integrity reports
- Optional Slack / webhook alerts
- Multisite awareness

No plans for upsells.
No plans for subscriptions.

---

## Author

**Luc Constantin**  
Developer & Consultant  
https://accolades.dev  

If this plugin helps you, you can support the work here:  
https://donate.stripe.com/bJeeVf50m3Spezm6vn8AE03

---

## License

GPL v2 or later  
Free to use, modify, and redistribute.


