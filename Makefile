.PHONY: help build run docker-build docker-up docker-down setup clean test

help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*##"; printf "\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  %-15s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build the application binary
	go build -o registry-webui .

run: ## Run the application locally
	go run main.go

setup: ## Run setup script (Windows)
	@powershell -ExecutionPolicy Bypass -File setup.ps1

docker-build: ## Build Docker image
	docker-compose build

docker-up: ## Start all services with docker-compose
	docker-compose up -d

docker-down: ## Stop all services
	docker-compose down

docker-logs: ## Show docker-compose logs
	docker-compose logs -f

clean: ## Clean build artifacts and data
	@if exist registry-webui del registry-webui
	@if exist data rmdir /s /q data
	@echo "Cleaned build artifacts and data"

test: ## Run tests
	go test -v ./...

deps: ## Install Go dependencies
	go mod download
	go mod tidy

.DEFAULT_GOAL := help
