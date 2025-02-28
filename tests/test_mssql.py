from kaititu import MSSql
from pytest import fixture
import re
import os

pattern=re.compile(r"^microsoft sql server \d{4}",re.IGNORECASE)

@fixture(scope="module")
def db() -> MSSql:
    return MSSql(os.getenv("MS1"),1433)

def test_network_auth(db) -> None:
    assert db.host == os.getenv("MS1") and pattern.search(db.version) is not None