# System Hardening with Packer

This repository provides a collection of Packer templates and associated scripts for building hardened machine images across different environments. The goal is to automate the process of securing systems according to publicly recognized security standards, enhancing their resilience against various threats.

## Project Structure

The project is organized into two main hardening categories:

- **Bare Metal Hardening**: Scripts and configurations tailored for physical or virtual machines intended for on-premise or dedicated server deployments.
- **Cloud Image Hardening**: Scripts and configurations specifically designed for creating secure base images for cloud platforms (e.g., AWS, Azure, GCP).

Each category has its own dedicated directory containing specific `README.md` files with detailed information about the hardening steps, supported standards, and usage instructions.

## Getting Started

To begin using these hardening templates, navigate to the relevant directory (`baremetal/` or `cloud/`) and consult the `README.md` file within for environment-specific instructions.

## Standards and Compliance

Our hardening efforts are guided by industry best practices and aim to align with recognized security benchmarks (e.g., CIS Benchmarks, HIPAA, PCI DSS where applicable).
