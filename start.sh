#!/bin/bash
echo "Starting CloudCompliance environment..."

# Check if LocalStack is running
if curl -s http://localhost:4566/_localstack/health > /dev/null 2>&1; then
  echo "LocalStack already running"
else
  echo "Starting LocalStack..."
  docker run --rm -d \
    --name localstack-cc \
    -p 4566:4566 \
    -p 4510-4559:4510-4559 \
    localstack/localstack:3.4.0

  echo "Waiting for LocalStack to be ready..."
  for i in $(seq 1 30); do
    if curl -s http://localhost:4566/_localstack/health | grep -q '"s3"'; then
      echo "LocalStack ready"
      break
    fi
    sleep 3
  done
fi

echo "Deploying infrastructure..."
cd terraform && terraform apply -var-file=local.tfvars -auto-approve
cd ..

echo "Running compliance report..."
cloudcompliance report

echo ""
echo "Starting dashboard at http://localhost:8080"
cloudcompliance serve
