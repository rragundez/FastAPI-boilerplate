import hashlib


class ScriptIntegrityError(Exception):
    """Raised when the script integrity check fails."""


def verify_script_integrity(script_path: str, expected_checksum: str):
    """Verifies the SHA256 checksum of the given script file.

    Raises ScriptIntegrityError if the checksum does not match.
    """
    with open(script_path, "rb") as f:
        file_bytes = f.read()
    checksum = hashlib.sha256(file_bytes).hexdigest()
    if checksum != expected_checksum:
        raise ScriptIntegrityError(
            f"Script integrity check failed for '{script_path}'. "
            "The file may have been modified or tampered with. "
            "If this change was intentional, update the expected SHA256 checksum of the script."
        )
