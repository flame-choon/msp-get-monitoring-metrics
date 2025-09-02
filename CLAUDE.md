# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a cross-account AWS resource monitoring service that collects infrastructure information from multiple AWS accounts and generates Word reports stored in S3. The service is containerized and deployed on AWS EC2 Graviton (ARM64) instances.

## Current Implementation Status

### ✅ Completed Features
1. **EC2 Resource Collection** (`ec2_cross_account.py`)
   - Lists EC2 instances from target account
   - Generates Word report with instance details
   - Includes ELB (ALB/NLB/Classic) information

2. **RDS Resource Collection** (`rds_cross_account.py`)
   - Lists RDS instances and clusters (Aurora)
   - Generates separate Word report
   - Includes backup and Multi-AZ information

3. **CloudFront Resource Collection** (`cloudfront_cross_account.py`)
   - Lists CloudFront distributions
   - Lists Origin Access Identities (OAI)
   - Generates separate Word report

4. **S3 Report Storage**
   - All reports uploaded to `s3://starbucks-bucket/metric-report/`
   - File naming: `ServiceName_YYYYMMDD_HHMM.docx`

### 🔧 Technical Stack
- **Language**: Python 3.11
- **Container**: Docker (ARM64/Graviton optimized)
- **Deployment**: EC2 Graviton instances
- **CI/CD**: GitHub Actions with OIDC
- **Dependencies**: 
  - boto3 (AWS SDK)
  - python-docx (Word generation)
  - pydantic-settings (Configuration)

## Development Commands

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
python ec2_cross_account.py

# Build Docker image for ARM64
docker build --platform linux/arm64 -t msp-ec2-monitor:latest .

# Run with docker-compose
docker-compose up --build
```

### Deployment
```bash
# Deploy to EC2 (via GitHub Actions)
git push origin main

# Manual deployment
./deploy-graviton.sh
```

## Configuration & Environment

### Required Environment Variables (.env)
```env
SOURCE_ACCOUNT_ID=144149479695
TARGET_ACCOUNT_ID=867099995276
ASSUME_ROLE_NAME=Starbucks-Monitoring-Metrics
SESSION_NAME=EC2ListingSession
AWS_REGION=ap-northeast-2
LOG_LEVEL=INFO
```

### IAM Setup

#### Source Account (144149479695)
- EC2 Instance Role: `Starbucks-Monitoring-Metrics`
- Required permissions:
  - `sts:AssumeRole` to target account role
  - S3 write access to `starbucks-bucket/metric-report/*`

#### Target Account (867099995276)
- Cross-account Role: `Starbucks-Monitoring-Metrics`
- Trust relationship: Allow source account role
- Required AWS Managed Policies:
  - `AmazonEC2ReadOnlyAccess`
  - `AmazonRDSReadOnlyAccess`
  - `CloudFrontReadOnlyAccess`
  - `CloudWatchReadOnlyAccess`

### Important Issues & Solutions

#### 1. ARM64/Graviton Compatibility
- **Issue**: `exec format error` when running on Graviton
- **Solution**: Build with `--platform linux/arm64` in Dockerfile

#### 2. Pydantic Core Module Error
- **Issue**: `ModuleNotFoundError: No module named 'pydantic_core._pydantic_core'`
- **Solution**: Install python3-dev and rebuild in single-stage Dockerfile

#### 3. NoneType in Word Generation
- **Issue**: Word document generation fails with None values
- **Solution**: Added `_safe_str()` method to handle None values

#### 4. Cross-Account Access Denied
- **Issue**: `AccessDenied` when calling AssumeRole
- **Solution**: Ensure correct role names and trust relationships

## Next Steps & Potential Enhancements

1. **Add More AWS Services**
   - Lambda functions
   - S3 buckets
   - VPC configurations
   - Route53 hosted zones

2. **Scheduling & Automation**
   - Implement cron job or EventBridge for periodic execution
   - Add SNS notifications for report generation

3. **Report Enhancements**
   - Add Excel export option
   - Include cost analysis
   - Add graphical charts

4. **Monitoring & Alerting**
   - CloudWatch metrics for application health
   - Error alerting via SNS/Slack

## Known Limitations

1. External ID for AssumeRole is currently hardcoded
2. Reports are generated sequentially (could be parallelized)
3. No retry mechanism for failed API calls
4. Maximum report size limited by Word document constraints

## Security Notes

- Never commit `.env` files with actual credentials
- Use `.env.example` for templates
- Rotate IAM credentials regularly
- Enable CloudTrail for audit logging
- Use External ID for additional security in cross-account access