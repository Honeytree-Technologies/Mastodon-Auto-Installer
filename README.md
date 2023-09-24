# Mastodon Deployment Script

This script is designed to automate the initial deployment of Mastodon and its related components using Docker and bash scripting.

## About the Script

- **Language**: Bash
- **Deployment**: Uses Docker images for deploying Mastodon containers.
- **Configuration**:
  - Option to deploy Elasticsearch (not deployed by default).
  - Customizable Postgres DB size (defaults is 256MB).
  - SSL certificate generation via Let's Encrypt for designated domains and Nginx setup.

## Pre-requisites

- Server or VPS with a minimum of 4GB Ram, 2 vCPU, and 65 GB storage.
- Ubuntu v20.04 LTS pre-installed.
- Open ports: 22922 (SSH), 443 and 80
- Machine should have internet access for fetching packages and Docker images.
- Pre-register the machine's IP with the domain for SSL certificate generation.
- An email delivery service or SMTP server.

## Deployment Steps

1. SSH into the machine and assume root privileges.
2. Create and navigate to a directory: `mkdir auto_script && cd auto_script`.
3. Copy the `auto_script.sh` script to the directory.
4. Set appropriate permissions: `sudo chmod +x auto_script.sh`.
5. On lines 395-399 of the script you must set the credentials for your SMTP server
6. Start the deployment: `./auto_script.sh`.
7. Input the requested details: username, email, domain name, DB size, Elasticsearch preference.
8. Accept terms of service as prompted.
9. Follow further on-screen instructions to complete the setup.

## Post Deployment

- Access Mastodon via the provided domain with the given admin credentials.
- SSH port defaults to 22922.
- fail2ban is activated with progressive blocking.

## Post-Installation Security Recommendations

Once you have successfully deployed Mastodon using this script, it's crucial to take additional steps to secure and harden your environment. 

Consider the following actions:

- **Regular Updates**: Ensure that all system packages and software are regularly updated to patch potential vulnerabilities.
- **Firewall Configuration**: Fine-tune your firewall settings to allow only necessary traffic and block potential threats.
- **User Access**: Limit or disable root access. Use sudo for administrative tasks and avoid using the root account for daily tasks.
- **Secure Passwords**: Implement strong password policies, and consider using password managers.
- **Two-Factor Authentication**: Where possible, enable 2FA for critical services and accounts.
- **Backup**: Regularly back up critical data and ensure backups are stored securely.
- **Monitoring & Logging**: Set up monitoring and logging to detect and alert on suspicious activities.
- **Application-Specific Security**: Explore and implement security best practices specifically tailored to Mastodon and any other applications you might be running.
- **Review and Audit**: Periodically review and audit your security settings and practices to ensure they are up-to-date with the latest threats and vulnerabilities.

It's essential to recognize that the security landscape is dynamic. Stay informed, and be proactive in securing your digital assets.


## Troubleshooting

### Known Errors

1. Error: "Could not get lock /var/lib/dpkg/lock-frontend..."
   - **Cause**: `unattended-upgr` process.
   - **Solution**: 
     ```bash
     sudo rm /var/lib/dpkg/lock-frontend
     ```
     Restart script and choose one of the SSL certificate options:
     a. Attempt to reinstall this existing certificate.
     b. Renew & replace the certificate.

