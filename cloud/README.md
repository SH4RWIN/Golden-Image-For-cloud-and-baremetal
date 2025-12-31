# Cloud Image Hardening

This directory contains Packer template and script for hardening cloud-specific machine images, optimized for AWS. The focus is on creating secure, production-ready base AMIs (Amazon Machine Images) that adhere to security best practices while being compatible with cloud environments.

## Hardening Script

-   `cloud_hardenV2.sh`: This script automates the hardening process for cloud images, including:
    -   **Core Packages**: Installation and enablement of essential security services (SSH, UFW, Auditd, AppArmor, Fail2Ban, Unattended Upgrades).
    -   **SSH Hardening**: Enforcing key-only authentication, disabling password authentication, and configuring client alive intervals.
    -   **Firewall (UFW)**: Configuring UFW to allow essential cloud traffic (SSH, HTTPS outbound) and access to the EC2 Instance Metadata Service (IMDS).
    -   **Kernel Hardening**: Applying `sysctl` settings for general kernel security.
    -   **Auditd Configuration**: Comprehensive auditing rules for identity changes, sudo, SSH, authentication, file deletion, permission changes, kernel modules, and system time.
    -   **AppArmor Enforcement**: Enabling AppArmor profiles for critical services.
    -   **Logging**: Hardening `journald` for persistent and compressed logging.
    -   **Disable Noisy Services**: Stopping and disabling non-essential services that might interfere with cloud operations.

## Usage

1.  **Review `cloud_hardenV2.sh`**: Understand the script's actions and customize any cloud-specific settings as needed.
2.  **Packer Template**: A corresponding Packer template (e.g., `aws-ubuntu-v1.pkr.hcl`) will reference this script during the image build process.
3.  **Build the Image**: Use Packer to build your hardened cloud image:

    ```bash
    packer init .

    packer build aws-ubuntu-v1.pkr.hcl
    ```

## Cloud Considerations

-   **AWS IMDS**: The firewall rules explicitly allow outbound access to `169.254.169.254` (the IMDS endpoint) which is crucial for cloud instance functionality.
-   **SSH Keys**: Assumes SSH key-pair authentication managed by the cloud provider.
-   **Security Groups**: Cloud security groups or network ACLs should be used in conjunction with UFW for comprehensive network security.

## Standards and Best Practices

The `cloud_hardenV2.sh` script is designed with an emphasis on cloud security best practices, aiming to provide a secure base image that can be further customized and integrated into a secure cloud environment.