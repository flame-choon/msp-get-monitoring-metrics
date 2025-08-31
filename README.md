# MSP Get Monitoring Metrics - Cross-Account EC2 Listing

이 프로젝트는 AWS Source 계정에서 Target 계정의 EC2 인스턴스 목록을 조회하는 Python 애플리케이션입니다.

## 기능

- AWS STS AssumeRole을 사용한 Cross-Account 접근
- EC2 인스턴스 목록 조회
- 태그 기반 인스턴스 필터링
- 실행 중인 인스턴스만 조회

## 사전 요구사항

### 1. Source Account IAM Role 설정

Source 계정의 EC2 인스턴스에 연결할 IAM Role에 다음 정책을 추가하세요:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::TARGET_ACCOUNT_ID:role/YOUR_CROSS_ACCOUNT_ROLE"
        }
    ]
}
```

### 2. Target Account IAM Role 생성

Target 계정에서 Cross-Account IAM Role을 생성하고 다음을 설정하세요:

#### Trust Relationship (신뢰 관계):
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::SOURCE_ACCOUNT_ID:root"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "unique-external-id"
                }
            }
        }
    ]
}
```

#### Role Policy (역할 정책):
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceStatus",
                "ec2:DescribeTags"
            ],
            "Resource": "*"
        }
    ]
}
```

## 설치 방법

1. 프로젝트 클론:
```bash
git clone <repository-url>
cd msp-get-monitoring-metrics
```

2. Python 가상환경 생성 및 활성화:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. 의존성 설치:
```bash
pip install -r requirements.txt
```

4. 환경 변수 설정:
```bash
cp .env.example .env
# .env 파일을 편집하여 필요한 값 설정
```

## 사용 방법

### 기본 실행
```bash
python ec2_cross_account.py
```

### 프로그래밍 방식으로 사용
```python
from ec2_cross_account import EC2CrossAccountManager

# 매니저 초기화
ec2_manager = EC2CrossAccountManager()

# 모든 인스턴스 조회
instances = ec2_manager.list_ec2_instances()

# 실행 중인 인스턴스만 조회
running_instances = ec2_manager.get_running_instances()

# 특정 태그를 가진 인스턴스 조회
tagged_instances = ec2_manager.get_instances_by_tag('Environment', 'Production')
```

## 배포

### Docker를 사용한 배포

#### 1. Docker 이미지 빌드
```bash
# 로컬에서 이미지 빌드
docker build -t msp-ec2-monitor:latest .

# 또는 docker-compose 사용
docker-compose build
```

#### 2. Docker 컨테이너 실행

**EC2 인스턴스에서 IAM Role 사용 시:**
```bash
# docker run 사용
docker run -d \
  --name ec2-monitor \
  --network host \
  -e SOURCE_ACCOUNT_ID=YOUR_SOURCE_ACCOUNT \
  -e TARGET_ACCOUNT_ID=YOUR_TARGET_ACCOUNT \
  -e ASSUME_ROLE_NAME=YOUR_ROLE_NAME \
  -e AWS_REGION=ap-northeast-2 \
  msp-ec2-monitor:latest

# 또는 docker-compose 사용
docker-compose up -d
```

**로컬 테스트 시 (AWS 자격 증명 사용):**
```bash
docker run -d \
  --name ec2-monitor \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  -e SOURCE_ACCOUNT_ID=YOUR_SOURCE_ACCOUNT \
  -e TARGET_ACCOUNT_ID=YOUR_TARGET_ACCOUNT \
  -e ASSUME_ROLE_NAME=YOUR_ROLE_NAME \
  -e AWS_REGION=ap-northeast-2 \
  msp-ec2-monitor:latest
```

#### 3. 로그 확인
```bash
# Docker 로그 확인
docker logs ec2-monitor

# docker-compose 로그 확인
docker-compose logs -f ec2-monitor
```

### 기존 방식 배포 (Docker 없이)

EC2 인스턴스에 직접 배포 시:

1. EC2 인스턴스에 적절한 IAM Role이 연결되어 있는지 확인
2. 애플리케이션 코드를 인스턴스에 복사
3. 의존성 설치 및 실행

```bash
# EC2 인스턴스에서
sudo yum install python3 python3-pip -y  # Amazon Linux 2
pip3 install -r requirements.txt
python3 ec2_cross_account.py
```

## 문제 해결

### AssumeRole 실패
- Source 계정의 IAM Role에 AssumeRole 권한이 있는지 확인
- Target 계정의 Trust Relationship이 올바르게 설정되었는지 확인
- Role ARN이 정확한지 확인

### EC2 조회 실패
- Target 계정의 Role에 EC2 읽기 권한이 있는지 확인
- 리전 설정이 올바른지 확인

## 보안 고려사항

- 프로덕션 환경에서는 External ID를 사용하여 추가 보안 제공
- 최소 권한 원칙에 따라 필요한 권한만 부여
- CloudTrail을 통해 Cross-Account 접근 모니터링

## GitHub Actions 배포

### 사전 준비

1. **GitHub Secrets 설정**:
   - `EC2_SSH_PRIVATE_KEY`: EC2 인스턴스 접속용 SSH 개인키
   - `AWS_ROLE_TO_ASSUME`: (OIDC 방식) IAM Role ARN
   - `AWS_ACCESS_KEY_ID`: (Access Key 방식) AWS Access Key
   - `AWS_SECRET_ACCESS_KEY`: (Access Key 방식) AWS Secret Key

2. **EC2 인스턴스 설정**:
   ```bash
   # EC2에 SSH 접속 후 실행
   curl -sSL https://raw.githubusercontent.com/<your-repo>/main/scripts/setup-ec2.sh | bash
   ```

### 배포 방법

#### 옵션 1: 직접 배포 (deploy.yml)
소스 코드를 EC2로 직접 전송하고 빌드:
```yaml
on:
  push:
    branches: [main]
```

#### 옵션 2: ECR + Access Key (deploy-with-ecr.yml)
AWS Access Key를 사용하여 ECR에 푸시:
```bash
# ECR 리포지토리 생성
aws ecr create-repository --repository-name msp-ec2-monitor --region ap-northeast-2
```

#### 옵션 3: ECR + OIDC (deploy-with-ecr-oidc.yml) - 권장
IAM Role 기반으로 안전하게 ECR에 푸시:

1. OIDC Provider 및 IAM Role 설정:
   ```bash
   # GitHub 사용자명 수정 후 실행
   cd iam
   ./setup-github-oidc.sh
   ```

2. 출력된 Role ARN을 GitHub Secrets에 추가:
   - `AWS_ROLE_TO_ASSUME`: arn:aws:iam::144149479695:role/GitHubActionsECRRole

3. EC2 인스턴스에 ECR 접근 권한 부여:
   ```bash
   # EC2 인스턴스의 IAM Role에 AmazonEC2ContainerRegistryReadOnly 정책 추가
   ```

워크플로우 파일 선택:
- `.github/workflows/deploy.yml` (직접 배포)
- `.github/workflows/deploy-with-ecr.yml` (ECR + Access Key)
- `.github/workflows/deploy-with-ecr-oidc.yml` (ECR + OIDC) - 권장

### 배포 프로세스

1. 코드를 main 브랜치에 푸시
2. GitHub Actions가 자동으로 배포 시작
3. EC2 인스턴스 54.180.161.84에 배포
4. Docker Compose로 컨테이너 실행

### 배포 확인

```bash
# EC2 인스턴스에서
cd /home/ec2-user/msp-ec2-monitor
docker-compose ps
docker-compose logs -f
```