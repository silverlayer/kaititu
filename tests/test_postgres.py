from kaititu import Postgres
from kaititu.audit.postgres import PostgresACR
from pytest import mark, fixture
import polars as pl
from . import *
import os

@fixture(scope="module")
def pg1() -> Postgres:
    return Postgres(os.getenv("PG1"),5432,os.getenv("LC_USER"),os.getenv("PASSWD"))

@fixture(scope="module")
def pg2() -> Postgres:
    return Postgres(os.getenv("PG2"),5432,os.getenv("LC_USER"),os.getenv("PASSWD"))

@mark.parametrize("pg,expected",[("pg1",os.getenv("PG1")),("pg2",os.getenv("PG2"))])
def test_basic_properties(pg: str, expected: bool, request) -> None:
    import re
    pattern=re.compile(r"^postgresql \d+\.\d+", re.IGNORECASE)
    db: Postgres = request.getfixturevalue(pg)
    assert db.host == expected and db.port == 5432\
    and pattern.search(db.version) is not None

@mark.parametrize("pg,expected",[("pg1",False),("pg2",False)])
def test_profile_login(pg: str, expected: bool, request) -> None:
    db: Postgres = request.getfixturevalue(pg)
    df=None
    with db.connect() as con:
        df=PostgresACR(con).profile_with_login()
    
    assert df.is_empty() == expected and has_columns(PROFILE_LOGIN,df.columns)

@mark.parametrize("pg,expected",[("pg1",False),("pg2",False)])
def test_role_nomember(pg: str, expected: bool, request) -> None:
    db: Postgres = request.getfixturevalue(pg)
    df=None
    with db.connect() as con:
        df=PostgresACR(con).role_without_members()

    assert df.is_empty() == expected and has_columns(ROLE_WITHOUT_MEMBERS_COLS,df.columns)


def test_profile_undue_privs(pg1: Postgres) -> None:
    df=None
    with pg1.connect() as con:
        df=PostgresACR(con).profile_undue_table_privileges()
    
    assert not df.is_empty() and has_columns(TABLE_UNDUE_PRIVILEGES_COLS,df.columns)


def test_no_profile_undue_privs(pg2: Postgres, monkeypatch) -> None:
    def mock_qry(variable,con) -> pl.DataFrame:
        variable=[]
        return pl.DataFrame({k: variable for k in TABLE_UNDUE_PRIVILEGES_COLS})
    
    monkeypatch.setattr(pl,"read_database",mock_qry)
    with pg2.connect() as con:
        df=PostgresACR(con).profile_undue_table_privileges()
    
    assert df.is_empty() and has_columns(TABLE_UNDUE_PRIVILEGES_COLS, df.columns)