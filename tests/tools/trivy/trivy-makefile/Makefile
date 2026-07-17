.PHONY: trivy scan

trivy:
	trivy fs --exit-code 1 .

scan: trivy
	@echo "Scan complete"
