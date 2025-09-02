import boto3
import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError, BotoCoreError
from config import settings
from datetime import datetime
from docx import Document
from docx.shared import Inches
import tempfile
import os

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CloudFrontCrossAccountManager:
    """Manages cross-account CloudFront distribution listing using AWS STS AssumeRole"""
    
    def __init__(self):
        self.source_account_id = settings.source_account_id
        self.target_account_id = settings.target_account_id
        self.assume_role_name = settings.assume_role_name
        self.session_name = settings.session_name
        self.region = settings.aws_region
        
    def assume_role(self) -> Dict[str, Any]:
        """
        Assume role in the target account
        
        Returns:
            Dict containing temporary credentials
        """
        try:
            # Create STS client using instance profile credentials
            sts_client = boto3.client('sts', region_name=self.region)
            
            # Construct the role ARN
            role_arn = f"arn:aws:iam::{self.target_account_id}:role/{self.assume_role_name}"
            
            logger.info(f"Attempting to assume role: {role_arn}")
            
            # Assume the role
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=self.session_name,
                DurationSeconds=3600,  # 1 hour
                ExternalId='starbucks-monitoring-secret-key-prod'  # Uncomment if using ExternalId
            )
            
            logger.info("Successfully assumed role in target account")
            return response['Credentials']
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"Failed to assume role: {error_code} - {error_message}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during assume role: {str(e)}")
            raise
    
    def create_cloudfront_client(self, credentials: Dict[str, Any]):
        """
        Create CloudFront client with assumed role credentials
        
        Args:
            credentials: Temporary credentials from assume_role
            
        Returns:
            CloudFront client object
        """
        # CloudFront is a global service, so we use us-east-1
        return boto3.client(
            'cloudfront',
            region_name='us-east-1',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    
    def list_cloudfront_distributions(self) -> List[Dict[str, Any]]:
        """
        List all CloudFront distributions in the target account
        
        Returns:
            List of CloudFront distribution information
        """
        try:
            # Assume role in target account
            credentials = self.assume_role()
            
            # Create CloudFront client with assumed credentials
            cf_client = self.create_cloudfront_client(credentials)
            
            # List all distributions
            logger.info(f"Retrieving CloudFront distributions from account {self.target_account_id}")
            
            distributions = []
            paginator = cf_client.get_paginator('list_distributions')
            
            for page in paginator.paginate():
                if 'Items' in page['DistributionList']:
                    for distribution in page['DistributionList']['Items']:
                        # Get detailed distribution information
                        dist_id = distribution['Id']
                        
                        # Get tags for the distribution
                        try:
                            tags_response = cf_client.list_tags_for_resource(Resource=f"arn:aws:cloudfront::{self.target_account_id}:distribution/{dist_id}")
                            tags = self._parse_tags(tags_response.get('Tags', {}).get('Items', []))
                        except Exception as tag_error:
                            logger.warning(f"Failed to get tags for distribution {dist_id}: {tag_error}")
                            tags = {}
                        
                        # Extract origin information
                        origins = []
                        for origin in distribution.get('Origins', {}).get('Items', []):
                            origin_info = {
                                'Id': origin.get('Id'),
                                'DomainName': origin.get('DomainName'),
                                'OriginPath': origin.get('OriginPath', ''),
                            }
                            # Check origin type
                            if 'S3OriginConfig' in origin:
                                origin_info['Type'] = 'S3'
                                origin_info['OAI'] = origin['S3OriginConfig'].get('OriginAccessIdentity', '')
                            elif 'CustomOriginConfig' in origin:
                                origin_info['Type'] = 'Custom'
                                origin_info['Protocol'] = origin['CustomOriginConfig'].get('OriginProtocolPolicy', '')
                            
                            origins.append(origin_info)
                        
                        distribution_info = {
                            'Id': dist_id,
                            'ARN': distribution.get('ARN'),
                            'DomainName': distribution.get('DomainName'),
                            'Status': distribution.get('Status'),
                            'Enabled': distribution.get('Enabled'),
                            'Comment': distribution.get('Comment', ''),
                            'PriceClass': distribution.get('PriceClass'),
                            'HttpVersion': distribution.get('HttpVersion'),
                            'IsIPV6Enabled': distribution.get('IsIPV6Enabled'),
                            'WebACLId': distribution.get('WebACLId', ''),
                            'LastModifiedTime': distribution.get('LastModifiedTime').isoformat() if distribution.get('LastModifiedTime') else '',
                            'Origins': origins,
                            'DefaultRootObject': distribution.get('DefaultRootObject', ''),
                            'Aliases': distribution.get('Aliases', {}).get('Items', []),
                            'Tags': tags
                        }
                        distributions.append(distribution_info)
            
            logger.info(f"Successfully retrieved {len(distributions)} CloudFront distributions")
            return distributions
            
        except Exception as e:
            logger.error(f"Failed to list CloudFront distributions: {str(e)}")
            raise
    
    def list_cloudfront_origin_access_identities(self) -> List[Dict[str, Any]]:
        """
        List all CloudFront Origin Access Identities in the target account
        
        Returns:
            List of OAI information
        """
        try:
            # Assume role in target account
            credentials = self.assume_role()
            
            # Create CloudFront client with assumed credentials
            cf_client = self.create_cloudfront_client(credentials)
            
            # List all OAIs
            logger.info(f"Retrieving CloudFront OAIs from account {self.target_account_id}")
            
            oais = []
            paginator = cf_client.get_paginator('list_cloud_front_origin_access_identities')
            
            for page in paginator.paginate():
                if 'Items' in page['CloudFrontOriginAccessIdentityList']:
                    for oai in page['CloudFrontOriginAccessIdentityList']['Items']:
                        oai_info = {
                            'Id': oai.get('Id'),
                            'S3CanonicalUserId': oai.get('S3CanonicalUserId'),
                            'Comment': oai.get('Comment', '')
                        }
                        oais.append(oai_info)
            
            logger.info(f"Successfully retrieved {len(oais)} CloudFront OAIs")
            return oais
            
        except Exception as e:
            logger.error(f"Failed to list CloudFront OAIs: {str(e)}")
            raise
    
    def _parse_tags(self, tags: List[Dict[str, str]]) -> Dict[str, str]:
        """
        Parse CloudFront tags into a dictionary
        
        Args:
            tags: List of tag dictionaries from CloudFront
            
        Returns:
            Dictionary of tag key-value pairs
        """
        return {tag.get('Key', ''): tag.get('Value', '') for tag in tags}
    
    def _safe_str(self, value: Any) -> str:
        """
        Safely convert any value to string, handling None values
        
        Args:
            value: Any value that needs to be converted to string
            
        Returns:
            String representation of the value, or empty string if None
        """
        if value is None:
            return ''
        if isinstance(value, bool):
            return 'Yes' if value else 'No'
        if isinstance(value, list):
            return ', '.join(str(item) for item in value)
        return str(value)
    
    def generate_cloudfront_word_report(self, distributions: List[Dict[str, Any]], oais: List[Dict[str, Any]]) -> str:
        """
        Generate Word document report with CloudFront data
        
        Args:
            distributions: List of CloudFront distribution information
            oais: List of Origin Access Identity information
            
        Returns:
            Path to generated Word document
        """
        try:
            # Create new document
            doc = Document()
            
            # Add title
            title = doc.add_heading('CloudFront Distribution Report', 0)
            
            # Add metadata
            doc.add_paragraph(f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
            doc.add_paragraph(f'Target Account: {self.target_account_id}')
            doc.add_paragraph(f'Total Distributions: {len(distributions)}')
            doc.add_paragraph(f'Total Origin Access Identities: {len(oais)}')
            doc.add_paragraph('')
            
            # CloudFront Distributions section
            doc.add_heading('CloudFront Distributions', 1)
            if not distributions:
                doc.add_paragraph('No CloudFront distributions found.')
            else:
                # Add table for distributions
                table = doc.add_table(rows=1, cols=8)
                table.style = 'Table Grid'
                
                # Header row
                headers = ['Distribution ID', 'Domain Name', 'Status', 'Enabled', 'Price Class', 'Origins Count', 'Comment', 'Name Tag']
                header_cells = table.rows[0].cells
                for i, header in enumerate(headers):
                    header_cells[i].text = header
                
                # Data rows
                for dist in distributions:
                    row_cells = table.add_row().cells
                    row_cells[0].text = self._safe_str(dist.get('Id'))
                    row_cells[1].text = self._safe_str(dist.get('DomainName'))
                    row_cells[2].text = self._safe_str(dist.get('Status'))
                    row_cells[3].text = self._safe_str(dist.get('Enabled'))
                    row_cells[4].text = self._safe_str(dist.get('PriceClass'))
                    row_cells[5].text = str(len(dist.get('Origins', [])))
                    row_cells[6].text = self._safe_str(dist.get('Comment'))[:50]  # Truncate long comments
                    row_cells[7].text = self._safe_str(dist.get('Tags', {}).get('Name'))
            
            doc.add_paragraph('')
            
            # Distribution Details section
            if distributions:
                doc.add_heading('Distribution Details', 1)
                for dist in distributions:
                    doc.add_heading(f"Distribution: {dist.get('Id')}", 2)
                    
                    # Basic info
                    doc.add_paragraph(f"Domain Name: {dist.get('DomainName')}")
                    doc.add_paragraph(f"Status: {dist.get('Status')}")
                    doc.add_paragraph(f"Enabled: {self._safe_str(dist.get('Enabled'))}")
                    doc.add_paragraph(f"Price Class: {dist.get('PriceClass')}")
                    
                    # Aliases
                    if dist.get('Aliases'):
                        doc.add_paragraph(f"Aliases: {', '.join(dist.get('Aliases'))}")
                    
                    # Origins
                    origins = dist.get('Origins', [])
                    if origins:
                        doc.add_paragraph("Origins:")
                        for origin in origins:
                            doc.add_paragraph(f"  - {origin.get('Id')}: {origin.get('DomainName')} ({origin.get('Type', 'Unknown')})", style='List Bullet')
                    
                    doc.add_paragraph('')
            
            # Origin Access Identities section
            doc.add_heading('Origin Access Identities', 1)
            if not oais:
                doc.add_paragraph('No Origin Access Identities found.')
            else:
                # Add table for OAIs
                table = doc.add_table(rows=1, cols=3)
                table.style = 'Table Grid'
                
                # Header row
                headers = ['OAI ID', 'S3 Canonical User ID', 'Comment']
                header_cells = table.rows[0].cells
                for i, header in enumerate(headers):
                    header_cells[i].text = header
                
                # Data rows
                for oai in oais:
                    row_cells = table.add_row().cells
                    row_cells[0].text = self._safe_str(oai.get('Id'))
                    row_cells[1].text = self._safe_str(oai.get('S3CanonicalUserId'))[:20] + '...'  # Truncate long ID
                    row_cells[2].text = self._safe_str(oai.get('Comment'))
            
            # Generate filename with current timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M")
            filename = f"CloudFront_{timestamp}.docx"
            
            # Create temporary file
            temp_dir = tempfile.mkdtemp()
            file_path = os.path.join(temp_dir, filename)
            
            # Save document
            doc.save(file_path)
            logger.info(f"CloudFront Word report generated: {file_path}")
            
            return file_path
            
        except Exception as e:
            logger.error(f"Failed to generate CloudFront Word report: {str(e)}")
            raise
    
    def upload_to_s3(self, file_path: str) -> str:
        """
        Upload file to S3 bucket
        
        Args:
            file_path: Path to local file to upload
            
        Returns:
            S3 object key (path)
        """
        try:
            # Create S3 client using instance profile credentials
            s3_client = boto3.client('s3', region_name=self.region)
            
            # Extract filename from path
            filename = os.path.basename(file_path)
            
            # Construct S3 key
            s3_key = f"{settings.s3_report_folder}/{filename}"
            
            logger.info(f"Uploading file to s3://{settings.s3_bucket_name}/{s3_key}")
            
            # Upload file
            s3_client.upload_file(
                file_path,
                settings.s3_bucket_name,
                s3_key
            )
            
            logger.info(f"Successfully uploaded file to S3: {s3_key}")
            return s3_key
            
        except Exception as e:
            logger.error(f"Failed to upload file to S3: {str(e)}")
            raise
    
    def generate_and_upload_cloudfront_report(self) -> str:
        """
        Generate CloudFront Word report and upload to S3
        
        Returns:
            S3 object key of uploaded file
        """
        try:
            # Get CloudFront distributions
            distributions = self.list_cloudfront_distributions()
            
            # Get CloudFront OAIs
            oais = self.list_cloudfront_origin_access_identities()
            
            # Generate Word report
            file_path = self.generate_cloudfront_word_report(distributions, oais)
            
            # Upload to S3
            s3_key = self.upload_to_s3(file_path)
            
            # Clean up temporary file
            try:
                os.remove(file_path)
                os.rmdir(os.path.dirname(file_path))
            except Exception as cleanup_error:
                logger.warning(f"Failed to clean up temporary file: {cleanup_error}")
            
            return s3_key
            
        except Exception as e:
            logger.error(f"Failed to generate and upload CloudFront report: {str(e)}")
            raise


def main():
    """Main function to demonstrate CloudFront cross-account listing"""
    try:
        # Initialize the manager
        cf_manager = CloudFrontCrossAccountManager()
        
        # List all CloudFront distributions
        print(f"\n=== Listing all CloudFront distributions in account {settings.target_account_id} ===")
        distributions = cf_manager.list_cloudfront_distributions()
        
        for dist in distributions:
            print(f"\nDistribution: {dist['Id']}")
            print(f"  Domain Name: {dist['DomainName']}")
            print(f"  Status: {dist['Status']}")
            print(f"  Enabled: {dist['Enabled']}")
            print(f"  Origins: {len(dist['Origins'])}")
            print(f"  Comment: {dist['Comment'][:50]}...")
            print(f"  Name: {dist['Tags'].get('Name', 'N/A')}")
        
        print(f"\nTotal CloudFront distributions: {len(distributions)}")
        
        # List all OAIs
        print(f"\n=== Listing all Origin Access Identities in account {settings.target_account_id} ===")
        oais = cf_manager.list_cloudfront_origin_access_identities()
        
        for oai in oais:
            print(f"\nOAI: {oai['Id']}")
            print(f"  Comment: {oai['Comment']}")
        
        print(f"\nTotal OAIs: {len(oais)}")
        
        # Generate and upload report
        print(f"\n=== Generating and uploading CloudFront Word report ===")
        s3_key = cf_manager.generate_and_upload_cloudfront_report()
        print(f"CloudFront report uploaded to: s3://{settings.s3_bucket_name}/{s3_key}")
        
    except Exception as e:
        logger.error(f"Error in main: {str(e)}")
        raise


if __name__ == "__main__":
    main()