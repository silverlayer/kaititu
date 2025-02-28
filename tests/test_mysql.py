from kaititu.audit.mysql import MySqlACR
from pytest import mark, raises, fixture
from kaititu import MySql
from . import *
import os

@fixture(scope="module")
def audit1() -> MySqlACR:
    return MySqlACR(MySql(os.getenv("MY1"),3307,os.getenv("LC_USER"),os.getenv("PASSWD")))

@fixture(scope="module")
def audit2() -> MySqlACR:
    return MySqlACR(MySql(os.getenv("MY2"),3306,os.getenv("LC_USER"),os.getenv("PASSWD")))

@mark.parametrize("audit,expected",[("audit1",(os.getenv("MY1"),3307)),("audit2",(os.getenv("MY2"),3306))])
def test_basic_properties(audit,expected,request) -> None:
    import re
    pattern=re.compile(r"^mysql \d+\.\d+\.\d+", re.IGNORECASE)
    mydb: MySql = request.getfixturevalue(audit).db
    host, port = expected
    assert mydb.host == host and mydb.port == port\
    and pattern.search(mydb.version) is not None

@mark.parametrize("audit,expected",[("audit1",False),("audit2",False)])
def test_profile_login(audit,expected,request) -> None:
    df=request.getfixturevalue(audit).profile_with_login()
    assert df.is_empty() == expected and has_columns(PROFILE_LOGIN,df.columns)

def test_role_without_members_MY1(audit1) -> None:
    with raises(NotImplementedError):
        audit1.role_without_members()

def test_role_without_members_MY2(audit2) -> None:
    df=audit2.role_without_members()
    assert not df.is_empty() and has_columns(ROLE_WITHOUT_MEMBERS_COLS,df.columns)

@mark.parametrize("audit,expected",[("audit1",False),("audit2",False)])
def test_undue_table_privileges(audit,expected,request) -> None:
    df=request.getfixturevalue(audit).profile_undue_table_privileges()
    assert df.is_empty() == expected and has_columns(TABLE_UNDUE_PRIVILEGES_COLS,df.columns)