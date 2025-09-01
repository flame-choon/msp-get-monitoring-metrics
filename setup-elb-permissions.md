# ELB 액세스를 위한 IAM 권한 설정

## 필요한 추가 권한

ELB 목록을 조회하기 위해 타겟 계정의 Cross-Account Role에 다음 권한을 추가해야 합니다:

### 타겟 계정(867099995276)에서 실행

#### 방법 1: AWS Console 사용
1. IAM → Roles → `Starbucks-Monitoring-Metrcis`
2. Permissions 탭 → Add permissions → Attach policies
3. 다음 Managed Policy 추가:
   - `ElasticLoadBalancingReadOnly`

#### 방법 2: AWS CLI로 Managed Policy 연결
```bash
aws iam attach-role-policy \
  --role-name Starbucks-Monitoring-Metrcis \
  --policy-arn arn:aws:iam::aws:policy/ElasticLoadBalancingReadOnly
```

#### 방법 3: 커스텀 인라인 정책 추가
```bash
aws iam put-role-policy \
  --role-name Starbucks-Monitoring-Metrcis \
  --policy-name ELBReadOnlyAccess \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeTags",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeListeners"
            ],
            "Resource": "*"
        }
    ]
}'
```

## 권한 설명

- `elasticloadbalancing:DescribeLoadBalancers`: ALB/NLB/Classic ELB 목록 조회
- `elasticloadbalancing:DescribeTags`: 로드밸런서 태그 정보 조회
- `elasticloadbalancing:DescribeTargetGroups`: 타겟 그룹 정보 조회 (선택사항)
- `elasticloadbalancing:DescribeListeners`: 리스너 정보 조회 (선택사항)

## 테스트

권한 설정 완료 후 다음 명령으로 테스트:

```bash
# ELBv2 (ALB/NLB) 테스트
aws elbv2 describe-load-balancers

# Classic ELB 테스트
aws elb describe-load-balancers
```

## 생성되는 파일

- **EC2 리포트**: `YYYYMMDD_HHMM.docx` (예: `20241201_1430.docx`)
- **ELB 리포트**: `ELB_YYYYMMDD_HHMM.docx` (예: `ELB_20241201_1430.docx`)

두 파일 모두 `s3://starbucks-bucket/metric-report/` 경로에 저장됩니다.