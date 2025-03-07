from kaititu import MSSql
from kaititu.audit.mssql import MSSqlACR
from pytest import fixture, mark
from polars import DataFrame
from . import *
import re
import os

pattern=re.compile(r"^microsoft sql server \d{4}",re.IGNORECASE)

@fixture(scope="module")
def sa_auth() -> MSSqlACR:
    return MSSqlACR(MSSql(os.getenv("MS1"),1440,os.getenv("MS1_USR"),os.getenv("MS1_PWD"),os.getenv("MS1_DB")))

@fixture(scope="module")
def win_auth() -> MSSqlACR:
    return MSSqlACR(MSSql(os.getenv("MS2"),1434,ins=os.getenv("MS2_DB")))

@mark.parametrize("audit,expected",[("sa_auth",(os.getenv("MS1"),1440)),("win_auth",(os.getenv("MS2"),1434))])
def test_basic_properties(audit,expected,request) -> None:
    db: MSSql = request.getfixturevalue(audit).db
    host, port = expected
    assert db.host == host and db.port == port and pattern.search(db.version) is not None

@mark.parametrize("audit",["sa_auth","win_auth"])
def test_profile_login(audit,request) -> None:
    df=request.getfixturevalue(audit).profile_with_login()
    assert not df.is_empty() and has_columns(PROFILE_LOGIN, df.columns)

@mark.parametrize("audit",["sa_auth","win_auth"])
def test_role_nomember(audit,request) -> None:
    df=request.getfixturevalue(audit).role_without_members()
    assert not df.is_empty() and has_columns(ROLE_WITHOUT_MEMBERS_COLS, df.columns)

@mark.parametrize("audit",["sa_auth","win_auth"])
def test_profile_undue_privs(audit,request) -> None:
    df=request.getfixturevalue(audit).profile_undue_table_privileges()
    assert not df.is_empty() and has_columns(TABLE_UNDUE_PRIVILEGES_COLS, df.columns)

def test_no_profile_undue_privs(sa_auth,monkeypatch) -> None:
    def mock_multi_qry(*args) -> DataFrame:
        variable=[]
        df=DataFrame({k: variable for k in TABLE_UNDUE_PRIVILEGES_COLS})
        return (df, df)
    
    monkeypatch.setattr(sa_auth.db,"multi_qry",mock_multi_qry)
    df=sa_auth.profile_undue_table_privileges()
    assert df.is_empty() and has_columns(TABLE_UNDUE_PRIVILEGES_COLS, df.columns)