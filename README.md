# KAITITU

## What is KAITITU?

KAITITU is a library to deal with common tasks on databases.
It has a generic API that helps on operational and analytical tasks for popular database management system.

## License

KAITITU is released under the terms of the Apache license v2.0. See LICENSE for information.

## Contributing

We welcome contributions from the community. Before submitting a pull request, please review our [contribution guide](./CONTRIBUTING.md).

## Getting started

KAITITU is available in [PyPI.org](https://pypi.org/), so the recommended method to install is `$ pip install kaititu`. Otherwise, you can download the source code and run by yourself.

In a nutshell, the first requirement is a subclass of `kaititu.Database`, it's resposible to manage database connections and calls.
The second piece is an instance of some class that uses `kaititu.Database`; for example, the `kaititu.audit.AccessControlReport` class.

With this minimum setup, you can use KAITITU like in the code sample below.

```python
from kaititu.audit.postgres import PostgresACR
from kaititu import Postgres

# the user must have privileges to read system objects of database
db=Postgres("127.0.0.1",5432,"dba","654321")

# print the database version as a banner 
print(db.version)

with db.connect() as connection:
    acr=PostgresACR(connection)
    # get profiles that have undue privileges on tables. See the docs for detail.
    result=acr.profile_undue_table_privileges()
    # print the corresponding polars.DataFrame
    print(result)
```

To better understanding KAITITU, read the [documentation](https://silverlayer.github.io/kaititu).