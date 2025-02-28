from kaititu import Postgres
from kaititu.audit.postgres import PostgresACR
from pytest import mark, fixture
from polars import DataFrame
from . import *
import os

@fixture(scope="module")
def audit1() -> PostgresACR:
    return PostgresACR(Postgres(os.getenv("PG1"),5432,os.getenv("LC_USER"),os.getenv("PASSWD")))

@fixture(scope="module")
def audit2() -> PostgresACR:
    return PostgresACR(Postgres(os.getenv("PG2"),5432,os.getenv("LC_USER"),os.getenv("PASSWD")))

@mark.parametrize("audit,expected",[("audit1",os.getenv("PG1")),("audit2",os.getenv("PG2"))])
def test_basic_properties(audit, expected, request) -> None:
    import re
    pattern=re.compile(r"^postgresql \d+\.\d+", re.IGNORECASE)
    pg=request.getfixturevalue(audit).db
    assert pg.host == expected and pg.port == 5432\
    and pattern.search(pg.version) is not None

@mark.parametrize("audit,expected",[("audit1",False),("audit2",False)])
def test_profile_login(audit, expected, request) -> None:
    df=request.getfixturevalue(audit).profile_with_login()
    assert df.is_empty() == expected and has_columns(PROFILE_LOGIN,df.columns)

@mark.parametrize("audit,expected",[("audit1",False),("audit2",False)])
def test_role_nomember(audit, expected, request) -> None:
    df=request.getfixturevalue(audit).role_without_members()
    assert df.is_empty() == expected and has_columns(ROLE_WITHOUT_MEMBERS_COLS,df.columns)


def test_profile_undue_privs(audit1) -> None:
    df=audit1.profile_undue_table_privileges()
    assert not df.is_empty() and has_columns(TABLE_UNDUE_PRIVILEGES_COLS,df.columns)


def test_no_profile_undue_privs(monkeypatch) -> None:
    def mock_single_qry(variable) -> DataFrame:
        variable=[]
        return DataFrame({k: variable for k in TABLE_UNDUE_PRIVILEGES_COLS})
    
    audit=PostgresACR(Postgres(os.getenv("PG1"),5432,os.getenv("LC_USER"),os.getenv("PASSWD")))
    monkeypatch.setattr(audit.db,"single_qry",mock_single_qry)
    df=audit.profile_undue_table_privileges()
    assert df.is_empty() and has_columns(TABLE_UNDUE_PRIVILEGES_COLS, df.columns)