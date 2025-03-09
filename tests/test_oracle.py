from kaititu import Oracle
from kaititu.audit.oracle import OracleACR
from pytest import fixture, mark
import polars as pl
from . import *
import os
import re

pattern=re.compile(r"^Oracle Database [\d\w\s]+ \d+.\d+.\d+.\d+.\d+", re.IGNORECASE)

@fixture(scope="module")
def orc1() -> Oracle:
    return Oracle(os.getenv("ORC1"),1521,os.getenv("LC_USER"),os.getenv("PASSWD"),os.getenv("ORC1_SN"))

@fixture(scope="module")
def orc2() -> Oracle:
    return Oracle(os.getenv("ORC2"),1521,os.getenv("LC_USER"),os.getenv("PASSWD"),os.getenv("ORC2_SN"))

@fixture(scope="module")
def orc3() -> Oracle:
    return Oracle(os.getenv("ORC3"),1521,os.getenv("LC_USER"),os.getenv("PASSWD"),os.getenv("ORC3_SN"))

@mark.parametrize("orc,expected",[
    ("orc1", os.getenv("ORC1")),
    ("orc2", os.getenv("ORC2")),
    ("orc3", os.getenv("ORC3"))
])
def test_basic_properties(orc: str,expected: str,request) -> None:
    db: Oracle = request.getfixturevalue(orc)
    assert db.host == expected and pattern.search(db.version) is not None

@mark.parametrize("orc",["orc1","orc2","orc3"])
def test_profile_login(orc: str, request) -> None:
    db: Oracle = request.getfixturevalue(orc)
    with db.connect() as con:
        df=OracleACR(con).profile_with_login()

    assert not df.is_empty() and has_columns(PROFILE_LOGIN, df.columns)

@mark.parametrize("orc",["orc1","orc2","orc3"])
def test_role_nomember(orc: str,request) -> None:
    db: Oracle = request.getfixturevalue(orc)
    with db.connect() as con:
        df=OracleACR(con).role_without_members()

    assert not df.is_empty() and has_columns(ROLE_WITHOUT_MEMBERS_COLS, df.columns)

@mark.parametrize("orc",["orc1","orc2","orc3"])
def test_profile_undue_privs(orc,request) -> None:
    db: Oracle = request.getfixturevalue(orc)
    with db.connect() as con:
        df=OracleACR(con).profile_undue_table_privileges()

    assert not df.is_empty() and has_columns(TABLE_UNDUE_PRIVILEGES_COLS, df.columns)

def test_no_profile_undue_privs(orc1: Oracle, monkeypatch) -> None:
    def mock_qry(variable, con) -> pl.DataFrame:
        variable=[]
        return pl.DataFrame({k: variable for k in TABLE_UNDUE_PRIVILEGES_COLS})

    monkeypatch.setattr(pl,"read_database",mock_qry)
    with orc1.connect() as con:
        df=OracleACR(con).profile_undue_table_privileges()

    assert df.is_empty() and has_columns(TABLE_UNDUE_PRIVILEGES_COLS, df.columns)