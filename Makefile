.PHONY: deploy deploy-prod validate report drift history destroy all

deploy:
	cd terraform && terraform init && terraform apply -var-file=local.tfvars -auto-approve

deploy-prod:
	cd terraform && terraform init && terraform apply -var-file=prod.tfvars -auto-approve

validate:
	cd terraform && terraform validate && terraform fmt -check

report:
	cloudcompliance report

drift:
	cloudcompliance drift

history:
	cloudcompliance history

history-export:
	cloudcompliance history --export

destroy:
	cd terraform && terraform destroy -var-file=local.tfvars -auto-approve

all: deploy report drift history
