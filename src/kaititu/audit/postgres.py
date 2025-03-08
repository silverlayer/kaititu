from sqlalchemy.engine import Connection
from kaititu.audit import AccessControlReport
from kaititu import Postgres
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
            conx (Connection): sqlalchemy Connection with postgres dialect

        Raises:
            TypeError: if **instance** is not a class or subclass of :class:`sqlalchemy.engine.Connection`
        """
        if not isinstance(conx,Connection) or conx.engine.dialect.name != "postgres":
            raise TypeError("provide an instance of sqlalchemy connection class with postgres dialect")
        
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
                pl.lit(self._db.socket).alias("SOCKET"),
                pl.lit(self._db.instance).alias("INSTANCE")
            )
        
        return df.with_columns(
            pl.col("PRIVILEGE").list.join(" | "),
            pl.lit(self._db.socket).alias("SOCKET"),
            pl.lit(self._db.instance).alias("INSTANCE")
        )
    

    def role_without_members(self) -> pl.DataFrame:
        return self._db.single_qry(
            """
            select upper(trim(rolname)) as "ROLE" 
            from pg_catalog.pg_roles 
            left join information_schema.applicable_roles on (rolname=role_name)
            where rolcanlogin=false and role_name is null
            """
        ).with_columns(
            pl.lit(self._db.socket).alias("SOCKET"),
            pl.lit(self._db.instance).alias("INSTANCE")
        )
    

    def profile_with_login(self) -> pl.DataFrame:
        return self._db.single_qry(
            """
            select upper(trim(rolname)) as "PROFILE" 
            from pg_catalog.pg_roles
            where rolcanlogin = true
            """
        ).with_columns(
            pl.lit(self._db.socket).alias("SOCKET"),
            pl.lit(self._db.instance).alias("INSTANCE")
        )