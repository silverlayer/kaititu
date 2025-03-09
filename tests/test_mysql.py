from kaititu.audit.mysql import MySqlACR
from pytest import mark, raises, fixture
from kaititu import MySql
import polars as pl
from . import *
import os

@fixture(scope="module")
def my1() -> MySql:
    return MySql(os.getenv("MY1"),3306,os.getenv("LC_USER"),os.getenv("PASSWD"))

@fixture(scope="module")
def my2() -> MySql:
    return MySql(os.getenv("MY2"),3306,os.getenv("LC_USER"),os.getenv("PASSWD"))

@mark.parametrize("my,expected",[("my1",(os.getenv("MY1"),3306)),("my2",(os.getenv("MY2"),3306))])
def test_basic_properties(my: str, expected: tuple[str,int], request) -> None:
    import re
    pattern=re.compile(r"^mysql \d+\.\d+\.\d+", re.IGNORECASE)
    mydb: MySql = request.getfixturevalue(my)
    host, port = expected
    assert mydb.host == host and mydb.port == port\
    and pattern.search(mydb.version) is not None

@mark.parametrize("my,expected",[("my1",False),("my2",False)])
def test_profile_login(my: str, expected: bool, request) -> None:
    db: MySql = request.getfixturevalue(my)
    with db.connect() as con:
        df=MySqlACR(con).profile_with_login()

    assert df.is_empty() == expected and has_columns(PROFILE_LOGIN,df.columns)

def test_role_without_members_MY1(my1: MySql) -> None:
    with my1.connect() as con:
        with raises(NotImplementedError):
            MySqlACR(con).role_without_members()

def test_role_without_members_MY2(my2: MySql) -> None:
    with my2.connect() as con:
        df=MySqlACR(con).role_without_members()

    assert not df.is_empty() and has_columns(ROLE_WITHOUT_MEMBERS_COLS,df.columns)

@mark.parametrize("my,expected",[("my1",False),("my2",False)])
def test_undue_table_privileges(my: str, expected: bool, request) -> None:
    db: MySql = request.getfixturevalue(my)
    with db.connect() as con:
        df=MySqlACR(con).profile_undue_table_privileges()

    assert df.is_empty() == expected and has_columns(TABLE_UNDUE_PRIVILEGES_COLS,df.columns)

def test_no_profile_undue_privs(my2: MySql, monkeypatch) -> None:
    def mock_qry(qry, con) -> pl.DataFrame:
        qry=[]
        return pl.DataFrame({k: qry for k in TABLE_UNDUE_PRIVILEGES_COLS})
    
    monkeypatch.setattr(pl,"read_database",mock_qry)
    with my2.connect() as con:
        df=MySqlACR(con).profile_undue_table_privileges()

    assert df.is_empty() and has_columns(TABLE_UNDUE_PRIVILEGES_COLS,df.columns)