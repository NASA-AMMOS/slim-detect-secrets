import pytest
from detect_secrets.plugins.absolute_filepath import AbsolutePathDetector


class TestAbsolutePathDetector:
    """
    Testing strategy

    Cover the cartesian product of these partitions:

      1. Partition on types of file paths:
        a. Absolute file paths
        b. Relative file paths

      2. Partition on line content:
        a. File path is the only content
        b. File path is part of a larger string

    And cover these cases:

      1. Partition on different operating systems (common os, leading characteristics)):
        a. Windows
        b. Unix (Linux, macOS)

      2. Partition on having environment variables:
        a. Has environment variables
        b. Does not have environment variables

      3. Partition on whitelist file paths:
        a. File path is in the whitelist
        b. File path is not in the whitelist
    """

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            # Absolute file paths, only content
            ('/var/log/nginx/access.log', True),
            (r'C:\Program Files\nginx\logs\access.log', True),
            # Absolute file paths, part of larger string
            ('Check the log at /var/log/nginx/access.log', True),
            (r'C:\Program Files\nginx\logs\access.log is the log file', True),
            # Relative file paths
            ('logs/access.log', False),
            (r'nginx\logs\access.log', False),
            # Whitelist file paths
            ('/usr/local/bin', False),
            ('/usr/bin', False),
            ('usr/bin/python', False),
            (r'C:\Windows\System32', False),
            # Non-whitelist file paths
            ('/home/user/.ssh/id_rsa', True),
            (r'C:\Users\user\.ssh\id_rsa', True),
            # File paths with environment variables
            ('$HOME/.ssh/id_rsa', False),
            (r'%USERPROFILE%\.ssh\id_rsa', False),
          ],
      )
    def test_analyze_line(self, payload, should_flag):
        logic = AbsolutePathDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
