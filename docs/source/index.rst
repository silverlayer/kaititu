Home
====

.. toctree::
   :maxdepth: 2
   :caption: Table of Contents

   package

What is |project|?
------------------

|project| is a library to deal with common tasks on databases.
It has a generic API that helps on operational and analytical tasks for popular database management system.

License
-------

|project| is released under the terms of the Apache license v2.0. See LICENSE for information.

Getting started
----------------

|project| is available in `PyPI.org <https://pypi.org/>`_, so the recommended method to install is :code:`$ pip install kaititu`. Otherwise, you can download the source code and run by yourself.

In a nutshell, the first requirement is a subclass of :class:`kaititu.Database`, it's resposible to manage database connections and calls.
The second piece is an instance of some class that uses :class:`kaititu.Database`; for example, the :class:`kaititu.audit.AccessControlReport` class.

With this minimum setup, you can use |project| like in the code sample below.

.. code-block:: python
   :linenos:

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


To better understanding |project|, read the documentation exploring the left-side menu.

|

Troubleshooting
---------------

Although the management of library dependencies is being handled, the drivers required by such libraries are not installed automatically. 
Therefore, make sure that the necessary drivers for connecting to Oracle, MS SQL Server, and others are functional on your operating system.

Polars doesn't work with older processors that lack `AVX2 <https://en.wikipedia.org/wiki/Advanced_Vector_Extensions#Advanced_Vector_Extensions_2>`_ instructions. So, if that's your situation, you'll need to replace `polars` with `polars-lts-cpu`. For more details, check the official `documentation <https://docs.pola.rs/user-guide/installation>`_.