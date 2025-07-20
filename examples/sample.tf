resource "aws_security_group" "example" {
  name        = "example_sg"
  description = "Example security group"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "example" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t2.micro"
  encrypted     = false
}

resource "aws_s3_bucket" "example" {
  bucket = "example-bucket"

  acl    = "public-read"
}
