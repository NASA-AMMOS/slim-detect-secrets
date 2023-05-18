import pytest
from detect_secrets.plugins.aws_sensitive_info import AWSSensitiveInfoDetectorExperimental

class TestAWSSensitiveInfoDetectorExperimental:
    """
      Testing strategy
    1. Partition on AWS resource type:
      a. AWS account id
      b. AWS ARN
      c. AWS security group id
      d. AWS VPC id
      e. AWS subnet id
      f. AWS bucket name (not implemented)
      g. AWS hostname
      
    2. Partition on presence or absence of keyword (if applicable):
      a. With keyword
      b. Without keyword (Wrong keyword)

    3. Parition by changing order of keyword (if applicable)
    """
    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            # AWS account id
            ('123456789012', True),
            ('12345678901', False),
            ('aws_account_id: 123456789012', True),
            # AWS ARN
            ('arn:aws:iam:us:123456789012', True),
            ('arn:aws:iam:cn:123456789012:role', True),
            ('arn:aws:iam::123456789012:user/johndoe', True),
            ('arn:aws:sns:us-east-1:123456789012:example-sns-topic-name', True),
            ('arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0e9801d129EXAMPLE', True),
            ('arn:aws:iam::12345678901', False),
            ('arn:aws', False),
            ('aws', False),
            # AWS security group id
            ('sg-12345678', True),
            ('sg-1234abcd', True),
            ('sg-12345678901234567', True),
            ('sg-1234abcd5678efghi czxcx', True),
            ('sg-12345678a', True),
            ('sg-1234567', False),
            ('sg-1234abc', False),
            ('sc-12345678', False),
            ('opera-dev-cluster-sg-collinss for keypair collinss', True),
            ('cluster_security_group_id=sg-037e6de521a3f4854', True),
            # AWS VPC id
            ('vpc-02676637ea26098a7', True),
            ('vpc-12345678901234567', True),
            ('vpc-1234abcd', True),
            ('vpc-12345678', True),
            ('vpc-12345678a', True),
            ('vpc-1234567', False),
            ('vpc-1234abc', False),
            ('vsc-12345678', False),
            # AWS subnet id
            ('subnet-12345678', True),
            ('subnet-1234abcd', True),
            ('subnet-12345678901234567', True),
            ('subnet-1234abcd5678efghij', True),
            ('subnet-12345678a', True),
            ('subnet-1234567', False),
            ('subnet-1234abc', False),
            ('subsc-12345678', False),
            # AWS hostname
            ('ip-10-24-34-0.ec2.internal', True),
            ('ip-10-24-34-0.us-west-2.compute.internal', True),
            ('ip-10-24-34-0', True),
            ('i-0123456789abcdef.ec2.internal', True),
            ('i-0123456789abcdef.us-west-2.compute.internal', True),
            ('i-0123456789abcdef', True),
            ('io-10-24-34-0.ec2.internal', False),
            ('ip.10.24.34.0.ec2.internal', False),
            ('ip-256-24-34-0.ec2.internal', True),
            ('ip-1024-24-34-0.ec2.internal', False),
            ('r-0123456789abcdef.ec2.internal', False),
            ('i-0123456789a.ec2.internal', False),
        ]
    )
    def test_analyze_line(self, payload, should_flag):
        logic = AWSSensitiveInfoDetectorExperimental()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
