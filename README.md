# Mastodon Deployment Script

Automate your Mastodon installation using this deployment script powered by Docker and Bash. Enhance the security of your Mastodon instance with just one command.

Whether you're working with a fresh server or an existing setup, this script is designed for both new and veteran Mastodon admins.

## Features

- 🚀 One-command deployment.
- 🔐 Enhancements to server security (SSH port change, firewall setup, Fail2Ban integration).
- 📘 Open-source and redistributable (a credit and shout out to Honeytree Technologies is greatly appreciated).

## Script Details

- **Language**: Bash
- **Deployment**: Docker-based Mastodon installation.
- **Configuration Options**:
  - Elasticsearch deployment (off by default).
  - Adjustable Postgres DB size (default: 256MB).
  - Automatic SSL certificate creation using Let's Encrypt along with Nginx configuration.

## Requirements

- Server or VPS with minimum 4GB RAM, 2 vCPU, and 65 GB storage.
- Ubuntu v22.04 LTS.
- Open ports: 22922 (SSH), 443, and 80.
- Active internet connection to fetch packages and Docker images.
- Domain name pointing to the server's IP address (necessary for SSL certification).
- An email delivery service or SMTP server.

## Installation Steps

1. Log into your server as the root user.
2. Execute the following command in your terminal:

    ```
    curl -sSL http://code.honeytreetech.com/fediverse/mastodon/auto-installer/auto_script.sh -o ./auto_script.sh && sudo chmod +x auto_script.sh && ./auto_script.sh
    ```

3. Follow the prompts to enter details like username, email, domain name, SMTP server information, DB size, Elasticsearch preference, etc.

## After Installation

- Visit your Mastodon instance using the provided domain.
- Default SSH port: 22922.
- Fail2Ban is active and set to block progressively.

## Security Recommendations

For optimal security post-installation, consider:

- **Regular Updates**: Keep system packages and applications up-to-date.
- **Firewall Tuning**: Restrict traffic to only necessary ports.
- **User Management**: Minimize or disable root access. Use sudo for admin tasks.
- **Password Policies**: Adopt strong passwords. Consider password manager usage.
- **Two-Factor Authentication (2FA)**: Enable 2FA for vital services/accounts.
- **Backups**: Create regular backups and store them securely.
- **Monitoring & Logging**: Monitor for unusual activities and set up alerts.
- **Application Security**: Research and apply Mastodon-specific security practices.
- **Periodic Review**: Regularly assess your security measures.

Staying informed and proactive is key in the digital security landscape.

## Troubleshooting

### Known Issues

1. **Error**: "Could not get lock /var/lib/dpkg/lock-frontend..."
   - **Cause**: `unattended-upgr` process.
   - **Fix**:

     ```bash
     sudo rm /var/lib/dpkg/lock-frontend
     ```
     Then, restart the script and pick an SSL certificate option:
     a. Try reinstalling the current certificate.
     b. Renew & replace the certificate.

## Credits

A big thank you to [Honeytree Technologies, LLC](https://honeytreetech.com) for making this script possible.

Stay connected with us on Mastodon: [@jeff@honeytree.social](https://honeytree.social/@jeff).
