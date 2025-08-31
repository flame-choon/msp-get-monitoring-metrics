#!/bin/bash
# EC2 인스턴스 초기 설정 스크립트

set -e

echo "=== EC2 인스턴스 설정 시작 ==="

# Docker 설치 확인 및 설치
if ! command -v docker &> /dev/null; then
    echo "Docker 설치 중..."
    sudo yum update -y
    sudo yum install -y docker
    sudo service docker start
    sudo usermod -a -G docker ec2-user
    echo "Docker 설치 완료"
else
    echo "Docker가 이미 설치되어 있습니다"
fi

# Docker Compose 설치 확인 및 설치
if ! command -v docker-compose &> /dev/null; then
    echo "Docker Compose 설치 중..."
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    echo "Docker Compose 설치 완료"
else
    echo "Docker Compose가 이미 설치되어 있습니다"
fi

# AWS CLI v2 설치 확인 (ECR 로그인용)
if ! aws --version | grep -q "aws-cli/2"; then
    echo "AWS CLI v2 설치 중..."
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    sudo ./aws/install
    rm -rf awscliv2.zip aws/
    echo "AWS CLI v2 설치 완료"
else
    echo "AWS CLI v2가 이미 설치되어 있습니다"
fi

# 배포 디렉토리 생성
mkdir -p /home/ec2-user/msp-ec2-monitor/logs

# Docker 서비스 자동 시작 설정
sudo systemctl enable docker

echo "=== EC2 인스턴스 설정 완료 ==="
echo "⚠️  재로그인하여 docker 그룹 권한을 활성화하세요: exit 후 다시 SSH 접속"