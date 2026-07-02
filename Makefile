.PHONY: deploy validate report destroy

deploy:
	cd terraform && terraform init && terraform apply -auto-approve

validate:
	cd terraform && terraform validate && terraform fmt -check

report:
	python compliance/report.py

destroy:
	cd terraform && terraform destroy -auto-approve

all: deploy report
