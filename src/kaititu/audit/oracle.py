from kaititu.audit import AccessControlReport
from sqlalchemy.engine import Connection
import polars as pl

class OracleACR(AccessControlReport):
    """
    Oracle access control report. Tested on oracle version >= 10g
    
    Note:
        The **INSTANCE** column is the Service Name where the queries are executed. 
    """
    def __init__(self, conx: Connection) -> None:
        """
        Initializer

        Args:
            conx (sqlalchemy.engine.Connection): Connection instance with oracle dialect

        Raises:
            TypeError: when **conx** is not a class or subclass of :class:`sqlalchemy.engine.Connection`
            ValueError: when connection's dialect is not oracle
        """
        OracleACR._check_connection_type(conx)
        if conx.engine.dialect.name != "oracle":
            raise ValueError("provide an instance of sqlalchemy connection class with oracle dialect")
        
        super().__init__(conx)

    def profile_with_login(self) -> pl.DataFrame:
        return pl.read_database(
            """
            SELECT DISTINCT GRANTEE AS "PROFILE",(SELECT INSTANCE_NAME FROM V$INSTANCE) AS "INSTANCE"
            FROM DBA_ROLE_PRIVS
            START WITH GRANTED_ROLE='CONNECT'
            CONNECT BY PRIOR GRANTEE=GRANTED_ROLE
            """,
            self._conx
        ).with_columns(pl.lit(self._socket).alias("SOCKET"))
    
    def role_without_members(self) -> pl.DataFrame:
        return pl.read_database(
            """
            SELECT "ROLE",(SELECT INSTANCE_NAME FROM V$INSTANCE) AS "INSTANCE" 
            FROM DBA_ROLES WHERE ROLE NOT IN (SELECT GRANTED_ROLE FROM DBA_ROLE_PRIVS)
            """,
            self._conx
        ).with_columns(pl.lit(self._socket).alias("SOCKET"))
    
    def profile_undue_table_privileges(self) -> pl.DataFrame:
        df = pl.read_database(
            """
            SELECT TP.GRANTEE AS "PROFILE",TP.OWNER AS "TABLE_SCHEMA",TP.TABLE_NAME,TP.PRIVILEGE,
            (SELECT INSTANCE_NAME FROM V$INSTANCE) AS "INSTANCE"
            FROM DBA_TAB_PRIVS TP
            WHERE TP.GRANTEE!=TP.OWNER
            AND TP.PRIVILEGE NOT IN (
                'READ','SELECT','REFERENCES','DEBUG',
                'EXECUTE','USE','QUERY REWRITE','ON COMMIT REFRESH'
            )
            AND EXISTS (
                SELECT 1 FROM DBA_USERS
                WHERE USERNAME=TP.OWNER
                AND DEFAULT_TABLESPACE NOT IN ('SYSTEM','SYSAUX')
            )
            AND EXISTS (
                SELECT 1 FROM DBA_TABLES
                WHERE TABLE_NAME=TP.TABLE_NAME
            )
            """,
            self._conx
        ).group_by("PROFILE","TABLE_SCHEMA","TABLE_NAME","INSTANCE").agg("PRIVILEGE")
        
        if df.is_empty():
            return df.with_columns(pl.lit(self._socket).alias("SOCKET"))
        
        return df.with_columns(
            pl.col("PRIVILEGE").list.join(" | "),
            pl.lit(self._socket).alias("SOCKET")
        )