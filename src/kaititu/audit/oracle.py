from kaititu.audit import AccessControlReport
from kaititu import Oracle
import polars as pl

class OracleACR(AccessControlReport):
    """
    Oracle access control report. Tested on oracle version >= 10g
    
    Note:
        The **INSTANCE** column is the Service Name where the queries are executed. 
    """
    def __init__(self, instance: Oracle) -> None:
        """
        Initializer

        Args:
            instance (Oracle): Oracle database instance

        Raises:
            TypeError: if **instance** is not a class or subclass of :class:`kaititu.Oracle`
        """
        if not isinstance(instance,Oracle):
            raise TypeError("provide an instance of Oracle class")
        
        super().__init__(instance)

    def profile_with_login(self) -> pl.DataFrame:
        return self._db.single_qry(
            """
            SELECT DISTINCT GRANTEE AS "PROFILE",(SELECT INSTANCE_NAME FROM V$INSTANCE) AS "INSTANCE"
            FROM DBA_ROLE_PRIVS
            START WITH GRANTED_ROLE='CONNECT'
            CONNECT BY PRIOR GRANTEE=GRANTED_ROLE
            """
        ).with_columns(pl.lit(self._db.socket).alias("SOCKET"))
    
    def role_without_members(self) -> pl.DataFrame:
        return self._db.single_qry(
            """
            SELECT "ROLE",(SELECT INSTANCE_NAME FROM V$INSTANCE) AS "INSTANCE" 
            FROM DBA_ROLES WHERE ROLE NOT IN (SELECT GRANTED_ROLE FROM DBA_ROLE_PRIVS)
            """
        ).with_columns(pl.lit(self._db.socket).alias("SOCKET"))
    
    def profile_undue_table_privileges(self) -> pl.DataFrame:
        df = self._db.single_qry(
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
            """
        ).group_by("PROFILE","TABLE_SCHEMA","TABLE_NAME","INSTANCE").agg("PRIVILEGE")
        
        if df.is_empty():
            return df.with_columns(pl.lit(self._db.socket).alias("SOCKET"))
        
        return df.with_columns(
            pl.col("PRIVILEGE").list.join(" | "),
            pl.lit(self._db.socket).alias("SOCKET")
        )