# 보안 설정 가이드

## GitHub에 Push하기 전 필수 설정

### 1. 환경 변수 설정

반드시 `.env` 파일을 생성하고 다음 값들을 설정하세요:

```bash
cp .env.example .env
# .env 파일 편집하여 실제 값 입력
```
### 2. GitHub Secrets 설정

GitHub Repository Settings > Secrets and variables > Actions에서 다음 Secrets를 추가하세요:

#### 필수 Secrets:
- `EC2_SSH_PRIVATE_KEY`: EC2 인스턴스 SSH 개인키
- `EC2_HOST`: EC2 인스턴스 IP 주소 (예: 1.2.3.4)
- `ECR_REPOSITORY`: ECR 리포지토리 경로 (예: your-account/repo-name)

#### OIDC 방식 사용 시:
- `AWS_ROLE_TO_ASSUME`: IAM Role ARN

#### Access Key 방식 사용 시:
- `AWS_ACCESS_KEY_ID`: AWS Access Key
- `AWS_SECRET_ACCESS_KEY`: AWS Secret Key

### 3. .env 파일 보안

`.env` 파일에는 실제 운영 값들이 포함되므로:
- 절대 Git에 커밋하지 마세요
- `.gitignore`에 포함되어 있는지 확인하세요
- 팀원들과 별도 채널로 공유하세요

### 4. 배포 전 체크리스트

- [ ] 모든 하드코딩된 AWS 계정 ID 제거됨
- [ ] EC2 IP 주소가 코드에 노출되지 않음
- [ ] IAM Role 이름이 환경변수로 관리됨
- [ ] .env 파일이 .gitignore에 포함됨
- [ ] GitHub Secrets가 모두 설정됨

## 주의사항

- 이 코드는 Cross-Account 접근을 수행하므로 IAM 권한을 최소한으로 제한하세요
- CloudTrail을 통해 모든 Cross-Account 활동을 모니터링하세요
- 정기적으로 IAM Role의 신뢰관계를 검토하세요