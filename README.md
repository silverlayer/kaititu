# KAITITU

## What is KAITITU?

Kaititu is a library to deal with common tasks on databases.
It has a generic API that helps on operational and analytical tasks for popular database management system.

## License

KAITITU is released under the terms of the Apache license v2.0. See LICENSE for information.

## Getting started

KAITITU is available in [PyPI.org](https://pypi.org/), so the recommended method to install is `$ pip install kaititu`. Otherwise, you can download the source code and run by yourself.

In a nutshell, the first requirement is a subclass of `kaititu.Database`, it's resposible to manage database connections and calls.
The second piece is an instance of some class that uses `kaititu.Database`; for example, the `kaititu.audit.AccessControlReport` class.

With this minimum setup, you can use KAITITU like in the code sample below.

```python
from kaititu.audit.mysql import MySqlACR
from kaititu import MySql

# the user must have privileges to read system objects of database
db=MySql("localhost",3306,"dba","654321")

# print the database version as a banner 
print(db.version)

acr=MySqlACR(db)
# get profiles that have undue privileges on tables. See the docs for detail.
result=acr.profile_undue_table_privileges()

# print the corresponding polars.DataFrame
print(result)
```

To better understanding KAITITU, read the documentation exploring the left-side menu.


### Attention

>Although the management of library dependencies is being handled, the drivers required by such libraries are not installed automatically. Therefore, make sure that the necessary drivers for connecting to Oracle, MS SQL Server, and others are functional on your operating system.
