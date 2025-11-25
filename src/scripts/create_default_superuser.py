"""This script creates the default super user and should only be used in certain scenarios, such as:

    - Initial setup of the application where no super user exists.
    - Recovery of super user access to the application when all super user accounts have been deleted or compromised.

Once human super users have been created through the application's standard user management processes,
it is recommended to delete or disable the default super user.

Do not change the default values for DEFAULT_USERNAME or DEFAULT_EMAIL or make them assignable via command-line
arguments. This will ensure there is a single known default super user account created by this script that can be
monitored and controlled.

Please set a strong password via the command-line argument when running this script.
"""

import asyncio
import json
import logging
import os
import sys

import fire
from app.api.v1.users import write_user_internal
from app.core.db.database import local_session
from app.core.security import get_password_hash
from app.schemas.user import UserCreateInternal
from fastcrud.exceptions.http_exceptions import DuplicateValueException

from . import CREATE_DEFAULT_SUPERUSER_CHECKSUM as EXPECTED_CHECKSUM
from .utils import ScriptIntegrityError, get_audit_info, verify_script_integrity

SCRIPT_PATH = os.path.abspath(__file__)
SCRIPT_NAME = os.path.basename(__file__)
logger = logging.getLogger(SCRIPT_NAME)
audit_info = get_audit_info(SCRIPT_PATH)
logger.warning(f"Script being run by: {json.dumps(audit_info, default=str, indent=2)}")

# Do not change these default values, read the file docstrings for context
DEFAULT_NAME = "Default Superuser"
DEFAULT_USERNAME = "defaultsuperuser"
DEFAULT_EMAIL = "default.superuser@superuser.com"


async def async_main(password: str):
    logger.info(f"Running script {SCRIPT_NAME}")
    logger.debug("Creating hashed password")
    hashed_password = get_password_hash(password)
    logger.debug("Preparing superuser data")
    superuser = UserCreateInternal(
        name=DEFAULT_NAME,
        username=DEFAULT_USERNAME,
        email=DEFAULT_EMAIL,
        hashed_password=hashed_password,
        is_superuser=True,
    )
    logger.debug("Creating database session")
    async with local_session() as db:
        try:
            logger.info("Writing default superuser to database.")
            result = await write_user_internal(user=superuser, db=db)
        except DuplicateValueException:
            user_details = {
                "name": superuser.name,
                "username": superuser.username,
                "email": superuser.email,
            }
            logger.warning(
                "Default superuser already exists with details:\n%s", json.dumps(user_details, default=str, indent=2)
            )
        else:
            user_details = {
                "id": result["id"],
                "name": result["name"],
                "username": result["username"],
                "email": result["email"],
                "profile_image_url": result["profile_image_url"],
                "uuid": result["uuid"],
                "created_at": result["created_at"],
                "updated_at": result["updated_at"],
                "deleted_at": result["deleted_at"],
                "is_deleted": result["is_deleted"],
                "is_superuser": result["is_superuser"],
                "tier_id": result["tier_id"],
            }
            logger.info("User created with details:\n%s", json.dumps(user_details, default=str, indent=2))


def main(password: str):
    """CLI entrypoint to create the default super user with a custom password.

    The default superuser details are:
        Name: Default Superuser
        Username: defaultsuperuser
        Email: default.superuser@superuser.com

    Please set a strong password via the command-line argument when running this script.

    Args:
        password (str): Password for the default super user.
    """
    asyncio.run(async_main(password=password))


if __name__ == "__main__":
    try:
        verify_script_integrity(SCRIPT_PATH, EXPECTED_CHECKSUM)
    except ScriptIntegrityError as e:
        logger.error(e)
        sys.exit(1)  # Exit with failure code
    else:
        fire.Fire(main)
