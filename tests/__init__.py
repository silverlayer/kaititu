TABLE_UNDUE_PRIVILEGES_COLS=["PROFILE","TABLE_SCHEMA","TABLE_NAME","PRIVILEGE","HOST","INSTANCE"]
ROLE_WITHOUT_MEMBERS_COLS=["ROLE","HOST","INSTANCE"]
PROFILE_LOGIN=["PROFILE","HOST","INSTANCE"]

def has_columns(required: list[str], applicant: list[str]) -> bool:
    """
    Check if all columns in required list exists in applicant list

    Args:
        required (list[str]): desirable columns
        applicant (list[str]): applicant columns for checking

    Returns:
        bool: True if all required columns exists in applicant. Otherwise, False.
    """
    for it in required:
        if not it in applicant:
            return False
    
    return True