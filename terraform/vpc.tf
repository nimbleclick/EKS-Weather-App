data "aws_availability_zones" "eks_azs" {}

resource "aws_vpc" "eks_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.tags, {
    Name = "EKS-VPC"
  })
}

resource "aws_subnet" "eks_public_subnets" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.eks_vpc.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.eks_azs.names[count.index]
  map_public_ip_on_launch = true

  tags = merge(var.tags, {
    Name                     = "EKS-Public-Subnet-${count.index + 1}"
    "kubernetes.io/role/elb" = 1
  })
}

resource "aws_subnet" "eks_private_subnets" {
  count                   = length(var.private_subnet_cidrs)
  vpc_id                  = aws_vpc.eks_vpc.id
  cidr_block              = var.private_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.eks_azs.names[count.index]
  map_public_ip_on_launch = false

  tags = merge(var.tags, {
    Name                              = "EKS-Private-Subnet-${count.index + 1}"
    "kubernetes.io/role/internal-elb" = 1
  })
}

resource "aws_internet_gateway" "eks_internet_gateway" {
  vpc_id = aws_vpc.eks_vpc.id

  tags = merge(var.tags, {
    name = "EKS-VPC-IG"
  })
}

resource "aws_route_table" "eks_public_route_table" {
  vpc_id = aws_vpc.eks_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.eks_internet_gateway.id
  }

  tags = merge(var.tags, {
    Name    = "Public-Route-Table",
    Network = "Public"
  })

  depends_on = [aws_internet_gateway.eks_internet_gateway]
}

resource "aws_route_table_association" "eks_public_route_table_association" {
  count          = length(aws_subnet.eks_public_subnets)
  route_table_id = aws_route_table.eks_public_route_table.id
  subnet_id      = aws_subnet.eks_public_subnets[count.index].id
}

resource "aws_route_table" "eks_private_route_tables" {
  count  = length(aws_subnet.eks_private_subnets)
  vpc_id = aws_vpc.eks_vpc.id

  tags = merge(var.tags, {
    Name = "Private-Route-Table-${count.index + 1}"
  })

  depends_on = [
    aws_internet_gateway.eks_internet_gateway,
    aws_nat_gateway.eks_nat_gateways]
}

resource "aws_route" "eks_private_route_table_routes" {
  count                  = length(aws_route_table.eks_private_route_tables)
  route_table_id         = aws_route_table.eks_private_route_tables[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.eks_nat_gateways[count.index].id
}

resource "aws_route_table_association" "eks_private_route_table_association" {
  count          = length(aws_subnet.eks_private_subnets)
  route_table_id = aws_route_table.eks_private_route_tables[count.index].id
  subnet_id      = aws_subnet.eks_private_subnets[count.index].id
}

resource "aws_nat_gateway" "eks_nat_gateways" {
  count         = length(aws_subnet.eks_public_subnets[*].id)
  subnet_id     = aws_subnet.eks_public_subnets[count.index].id
  allocation_id = aws_eip.eks_eips[count.index].id

  tags = merge(var.tags, {
    Name = "EKS-NAT-Gateway-${count.index + 1}"
  })
  
  depends_on = [
    aws_internet_gateway.eks_internet_gateway,
    aws_eip.eks_eips,
    aws_subnet.eks_public_subnets
  ]
}

resource "aws_eip" "eks_eips" {
  count  = length(aws_subnet.eks_public_subnets[*].id)
  domain = "vpc"

  tags = merge(var.tags, {
    Name = "EKS-EIP-${count.index + 1}"
  })
}

resource "aws_security_group" "eks_controlplane_security_group" {
  name   = "EKS-Controlplane-Security-Group"
  vpc_id = aws_vpc.eks_vpc.id

  tags = merge(var.tags, {
    Name = "EKS-Controlplane-Security-Group"
  })
}

resource "aws_vpc_security_group_egress_rule" "eks_controlplane_egress_rule" {
  security_group_id = aws_security_group.eks_controlplane_security_group.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"

  tags = merge(var.tags)
}