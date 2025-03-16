from kaititu import MSSql
from kaititu.audit.mssql import MSSqlACR
from pytest import fixture, mark
import polars as pl
from . import *
import re
import os

pattern=re.compile(r"^microsoft sql server \d{4}",re.IGNORECASE)

@fixture(scope="module")
def sa_auth() -> MSSql:
    return MSSql(os.getenv("MS1"),1440,os.getenv("MS1_USR"),os.getenv("MS1_PWD"),os.getenv("MS1_DB"))

@fixture(scope="module")
def win_auth() -> MSSql:
    return MSSql(os.getenv("MS2"),1434,ins=os.getenv("MS2_DB"))

@mark.parametrize("mssql,expected",[("sa_auth",(os.getenv("MS1"),1440)),("win_auth",(os.getenv("MS2"),1434))])
def test_basic_properties(mssql: str, expected: tuple[str,int], request) -> None:
    db: MSSql = request.getfixturevalue(mssql)
    host, port = expected
    assert db.host == host and db.port == port and pattern.search(db.version) is not None

@mark.parametrize("mssql",["sa_auth","win_auth"])
def test_profile_login(mssql: str, request) -> None:
    db: MSSql = request.getfixturevalue(mssql)
    with db.connect() as con:
        df=MSSqlACR(con).profile_with_login()

    assert not df.is_empty() and has_columns(PROFILE_LOGIN, df.columns)

@mark.parametrize("mssql",["sa_auth","win_auth"])
def test_role_nomember(mssql: str, request) -> None:
    db: MSSql = request.getfixturevalue(mssql)
    with db.connect() as con:
        df = MSSqlACR(con).role_without_members()

    assert df.is_empty() and has_columns(ROLE_WITHOUT_MEMBERS_COLS, df.columns)

@mark.parametrize("mssql",["sa_auth","win_auth"])
def test_profile_undue_privs(mssql: str, request) -> None:
    db: MSSql = request.getfixturevalue(mssql)
    with db.connect() as con:
        df = MSSqlACR(con).profile_undue_table_privileges()
    
    assert not df.is_empty() and has_columns(TABLE_UNDUE_PRIVILEGES_COLS, df.columns)

def test_no_profile_undue_privs(sa_auth: MSSql, monkeypatch) -> None:
    def mock_qry(one, two) -> pl.DataFrame:
        one=[]
        return pl.DataFrame({k: one for k in TABLE_UNDUE_PRIVILEGES_COLS})
    
    monkeypatch.setattr(pl,"read_database",mock_qry)
    with sa_auth.connect() as con:
        df=MSSqlACR(con).profile_undue_table_privileges()

    assert df.is_empty() and has_columns(TABLE_UNDUE_PRIVILEGES_COLS, df.columns)

@mark.parametrize("mssql,expected",[("sa_auth",0),("win_auth",55)])
def test_all_db_profile_with_login(mssql: str, expected: int, request) -> None:
    db: MSSql = request.getfixturevalue(mssql)
    with db.connect() as con:
        df=MSSqlACR(con).all_profile_with_login().unique("INSTANCE")
        final_inst=con.exec_driver_sql("select db_name()").scalar()

    assert df.shape[0] > expected and db.instance == final_inst

def test_all_db_role_without_members(win_auth: MSSql) -> None:
    with win_auth.connect() as con:
        df=MSSqlACR(con).all_role_without_members()
        final_inst=con.exec_driver_sql("select db_name()").scalar()

    assert df.shape[0] == 2 and win_auth.instance == final_inst

def test_all_db_profile_undue_table_privileges(sa_auth: MSSql) -> None:
    with sa_auth.connect() as con:
        df=MSSqlACR(con).all_profile_undue_table_privileges()

    assert df.shape[0] > 200