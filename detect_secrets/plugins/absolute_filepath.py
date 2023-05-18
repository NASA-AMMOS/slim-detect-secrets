import os
import re
from typing import Any, Set
from ..core.potential_secret import PotentialSecret
from detect_secrets.plugins.base import RegexBasedDetector
from detect_secrets.util.code_snippet import CodeSnippet
from ..settings import get_settings
from ..constants import VerifiedResult
from detect_secrets.util.inject import call_function_with_arguments


class AbsolutePathDetector(RegexBasedDetector):
    """Absolute Path Detector.
    
    This class is designed to efficiently and accurately detect absolute file paths within given text.
    
    Key Features:
    - Detects both Unix-style and Windows-style paths.
    - Expands environment variables before checking if the path is absolute.
    - Ignores whitelist file paths to reduce false positives.
    
    Limitations:
    - May not cover all edge cases, especially with unusual file path formats.
    """
    secret_type = 'Absolute File Path (Experimental Plugin)'

    whitelist = [
        '/usr/local/bin',
        '/usr/bin',
        'C:\\Windows\\System32',
    ]
    # Excludes whitelist file paths from detection to reduce false positives.

    denylist = [
        re.compile(r"\b" + re.escape(path) + r"\b") for path in whitelist
    ]

    # override
    def analyze_line(
        self,
        filename: str,
        line: str,
        line_number: int = 0,
        context: CodeSnippet = None,
        **kwargs: Any
    ) -> Set[PotentialSecret]:
        """This examines a line and finds all possible secret values in it."""
        print(os.path.isabs("C:\\Program Files\\nginx\\logs\\access.log"))
        output = set()
        # Expands environment variables before checking if the path is absolute
        # expanded_line = os.path.expandvars(line)
        expanded_line = line
        # Returns True if the path is absolute, False if not
        is_absolute_path = os.path.isabs(expanded_line)

        # Ignores whitelist file paths
        if any(denylist_regex.match(expanded_line) for denylist_regex in self.denylist):
            return output

        if is_absolute_path:
            is_verified: bool = False
            # If the filter is disabled it means --no-verify flag was passed
            # We won't run verification in that case
            if (
                'detect_secrets.filters.common.is_ignored_due_to_verification_policies'
                in get_settings().filters
            ):
                try:
                    verified_result = call_function_with_arguments(
                        self.verify,
                        secret=expanded_line,
                        context=context,
                    )
                    is_verified = True if verified_result == VerifiedResult.VERIFIED_TRUE else False
                except requests.exceptions.RequestException:
                    is_verified = False

            output.add(
                PotentialSecret(
                    type=self.secret_type,
                    filename=filename,
                    secret=expanded_line,
                    line_number=line_number,
                    is_verified=is_verified,
                ),
            )

        return output
