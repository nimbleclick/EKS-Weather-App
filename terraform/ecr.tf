resource "aws_ecr_repository" "eks_python_weather_app" {
  name                 = "eks-python-weather-app"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(var.tags)
}