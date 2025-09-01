# Cross-Account Access Setup Guide

## 문제 해결

현재 발생한 에러는 환경변수가 제대로 설정되지 않아서 발생했습니다:
- `TARGET_ACCOUNT_ID`가 `YOUR_TARGET_ACCOUNT_ID`로 설정됨
- `ASSUME_ROLE_NAME`이 `YOUR_CROSS_ACCOUNT_ROLE_NAME`으로 설정됨

## 해결 방법

### 1. EC2 인스턴스에서 .env 파일 수정

EC2에 SSH로 접속한 후:

```bash
cd /home/ec2-user/msp-ec2-monitor
vi .env
```

다음과 같이 실제 값으로 수정:
```env
# Source account (현재 EC2가 실행중인 계정)
SOURCE_ACCOUNT_ID=YOUR_SOURCE_ACCOUNT_ID

# Target account (모니터링하려는 대상 계정)
TARGET_ACCOUNT_ID=실제_대상_계정_ID

# Cross-account role name (대상 계정에 있는 역할 이름)
ASSUME_ROLE_NAME=실제_역할_이름

# 기타 설정
SESSION_NAME=EC2ListingSession
AWS_REGION=ap-northeast-2
LOG_LEVEL=INFO
```

### 2. 대상 계정(Target Account)에서 IAM Role 생성

대상 계정의 AWS Console에서:

1. IAM → Roles → Create role
2. "Custom trust policy" 선택
3. 다음 Trust Policy 입력:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::YOUR_SOURCE_ACCOUNT_ID:role/YOUR_EC2_ROLE_NAME"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

4. Permissions 추가:
   - `AmazonEC2ReadOnlyAccess` (또는 필요한 권한)

5. Role name 설정 (예: `CrossAccountEC2Reader`)

### 3. 컨테이너 재시작

```bash
cd /home/ec2-user/msp-ec2-monitor

# 기존 컨테이너 중지
docker-compose -f docker-compose.prod.yml down

# 새로운 환경변수로 재시작
docker-compose -f docker-compose.prod.yml up -d

# 로그 확인
docker-compose -f docker-compose.prod.yml logs -f
```

## 예시 설정

예시 - 대상 계정 ID가 `123456789012`이고, 역할 이름이 `CrossAccountEC2Reader`라면:


```env
SOURCE_ACCOUNT_ID=YOUR_SOURCE_ACCOUNT_ID
TARGET_ACCOUNT_ID=YOUR_TARGET_ACCOUNT_ID
ASSUME_ROLE_NAME=CrossAccountEC2Reader
SESSION_NAME=EC2ListingSession
AWS_REGION=ap-northeast-2
LOG_LEVEL=INFO
```

## 권한 체크리스트

✅ Source Account:
- EC2 인스턴스 Role: 소스 계정의 EC2 인스턴스에 할당된 IAM Role
- 필요 권한: `sts:AssumeRole`

✅ Target Account:
- Cross-account Role 생성 필요
- Trust relationship에 Source Account Role ARN 추가
- EC2 읽기 권한 부여

## 디버깅

문제가 계속되면 다음을 확인:

1. 환경변수 확인:
```bash
docker exec ec2-cross-account-monitor env | grep -E "ACCOUNT|ROLE"
```

2. IAM Role Trust Relationship 확인
3. Source Account Role의 AssumeRole 권한 확인