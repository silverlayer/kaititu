from sqlalchemy.engine import Connection
from kaititu.audit import AccessControlReport
import polars as pl

class PostgresACR(AccessControlReport):
    """
    Postgres access control report. Tested on postgres version >= 8.4

    Note:
        The **INSTANCE** column is the database where the queries are executed.
    """

    def __init__(self, conx: Connection) -> None:
        """
        Initializer

        Args:
            conx (sqlalchemy.engine.Connection): Connection instance with postgresql dialect

        Raises:
            TypeError: when **conx** is not a class or subclass of :class:`sqlalchemy.engine.Connection`
            ValueError: when connection's dialect is not postgresql
        """
        PostgresACR._check_connection_type(conx)
        if conx.engine.dialect.name != "postgresql":
            raise ValueError("provide an instance of sqlalchemy connection class with postgresql dialect")
        
        super().__init__(conx)


    def profile_undue_table_privileges(self) -> pl.DataFrame:
        df = pl.read_database(
            """
            select tp.grantee as "PROFILE",tp.table_schema as "TABLE_SCHEMA",
            tp.table_name as "TABLE_NAME",tp.privilege_type as "PRIVILEGE" 
            from information_schema.table_privileges tp
            where tp.grantee!=tp.table_schema
            and tp.privilege_type not in ('SELECT','REFERENCES')
            and exists (
                select 1 from pg_catalog.pg_roles
                where rolsuper=false and rolname=tp.grantee
            )
            """,
            self._conx
        ).group_by("PROFILE","TABLE_SCHEMA","TABLE_NAME").agg(pl.col("PRIVILEGE"))
        
        if df.is_empty():
            return df.with_columns(
                pl.lit(self._socket).alias("SOCKET"),
                pl.lit(self._instance).alias("INSTANCE")
            )
        
        return df.with_columns(
            pl.col("PRIVILEGE").list.join(" | "),
            pl.lit(self._socket).alias("SOCKET"),
            pl.lit(self._instance).alias("INSTANCE")
        )
    

    def role_without_members(self) -> pl.DataFrame:
        return pl.read_database(
            """
            select upper(trim(r.rolname)) as "ROLE"
            from pg_catalog.pg_roles r
            where r.rolcanlogin=false
            and not exists (
                select 1 
                from pg_catalog.pg_auth_members 
                where roleid=r.oid
            )
            """,
            self._conx
        ).with_columns(
            pl.lit(self._socket).alias("SOCKET"),
            pl.lit(self._instance).alias("INSTANCE")
        )
    

    def profile_with_login(self) -> pl.DataFrame:
        return pl.read_database(
            """
            select upper(trim(rolname)) as "PROFILE" 
            from pg_catalog.pg_roles
            where rolcanlogin = true
            """,
            self._conx
        ).with_columns(
            pl.lit(self._socket).alias("SOCKET"),
            pl.lit(self._instance).alias("INSTANCE")
        )