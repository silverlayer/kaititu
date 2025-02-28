from kaititu import Oracle
from kaititu.audit.oracle import OracleACR
from pytest import fixture, mark
from polars import DataFrame
from . import *
import os
import re

pattern=re.compile(r"^Oracle Database [\d\w\s]+ \d+.\d+.\d+.\d+.\d+", re.IGNORECASE)

@fixture(scope="module")
def audit1() -> OracleACR:
    return OracleACR(Oracle(os.getenv("ORC1"),1521,os.getenv("LC_USER"),os.getenv("PASSWD"),os.getenv("ORC1_SN")))

@fixture(scope="module")
def audit2() -> OracleACR:
    return OracleACR(Oracle(os.getenv("ORC2"),1522,os.getenv("LC_USER"),os.getenv("PASSWD"),os.getenv("ORC2_SN")))

@fixture(scope="module")
def audit3() -> OracleACR:
    return OracleACR(Oracle(os.getenv("ORC3"),1522,os.getenv("LC_USER"),os.getenv("PASSWD"),os.getenv("ORC3_SN")))

@mark.parametrize("audit,expected",[
    ("audit1", os.getenv("ORC1")),
    ("audit2", os.getenv("ORC2")),
    ("audit3", os.getenv("ORC3"))
])
def test_basic_properties(audit,expected,request) -> None:
    oc=request.getfixturevalue(audit).db
    assert oc.host == expected and pattern.search(oc.version) is not None

@mark.parametrize("audit",["audit1","audit2","audit3"])
def test_profile_login(audit,request) -> None:
    df=request.getfixturevalue(audit).profile_with_login()
    assert not df.is_empty() and has_columns(PROFILE_LOGIN, df.columns)

@mark.parametrize("audit",["audit1","audit2","audit3"])
def test_role_nomember(audit,request) -> None:
    df=request.getfixturevalue(audit).role_without_members()
    assert not df.is_empty() and has_columns(ROLE_WITHOUT_MEMBERS_COLS, df.columns)

@mark.parametrize("audit",["audit1","audit2","audit3"])
def test_profile_undue_privs(audit,request) -> None:
    df=request.getfixturevalue(audit).profile_undue_table_privileges()
    assert not df.is_empty() and has_columns(TABLE_UNDUE_PRIVILEGES_COLS, df.columns)

def test_no_profile_undue_privs(monkeypatch) -> None:
    def mock_single_qry(variable) -> DataFrame:
        variable=[]
        return DataFrame({k: variable for k in TABLE_UNDUE_PRIVILEGES_COLS})
    
    audit=OracleACR(Oracle(os.getenv("ORC1"),1521,os.getenv("LC_USER"),os.getenv("PASSWD"),os.getenv("ORC1_SN")))
    monkeypatch.setattr(audit.db,"single_qry",mock_single_qry)
    df=audit.profile_undue_table_privileges()
    assert df.is_empty() and has_columns(TABLE_UNDUE_PRIVILEGES_COLS, df.columns)