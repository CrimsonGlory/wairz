terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
    # Drive the in-apply image build/push + SPA publish (deploy.tf).
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3"
    }
  }

  # Remote state is recommended for any shared/team deployment. Copy
  # backend.tf.example to backend.tf, fill in your S3 bucket + DynamoDB lock
  # table, then `terraform init -migrate-state`. Local state is used until then.
}
