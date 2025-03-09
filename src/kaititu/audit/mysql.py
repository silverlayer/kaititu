from kaititu.audit import AccessControlReport
from sqlalchemy.engine import Connection
import polars as pl
import re

class MySqlACR(AccessControlReport):
    """
    MySQL access control report. Tested on MySQL version >= 5.

    Note:
        The **INSTANCE** column is always 'mysql', no matter which database is chosen. 
    """
    def __init__(self, conx: Connection) -> None:
        """
        Initializer

        Args:
            conx (sqlalchemy.engine.Connection): Connection instance with mysql dialect

        Raises:
            TypeError: when **conx** is not a class or subclass of :class:`sqlalchemy.engine.Connection`
            ValueError: when connection's dialect is not mysql
        """
        MySqlACR._check_connection_type(conx)
        if conx.engine.dialect.name != "mysql":
            raise ValueError("provide an instance of sqlalchemy connection class with mysql dialect")
        
        super().__init__(conx)
        # major version number
        ver=re.search(r"(\d+)\.\d+\.\d+",conx.info["version"])
        if not ver: raise ValueError("Invalid MySQL host: "+conx.info["version"])
        self._verno=int(ver.group(1))

    def profile_with_login(self) -> pl.DataFrame:
        return pl.read_database(
            """select distinct replace(grantee,'''','') as `PROFILE` from information_schema.USER_PRIVILEGES"""
            if self._verno<8 else
            """
            select concat('''',user,'''','@','''',host,'''') as `PROFILE` from mysql.user
            where password_expired='N' and account_locked='N' and length(authentication_string)>0
            """,
            self._conx
        ).with_columns(
            pl.lit(self._socket).alias("SOCKET"),
            pl.lit("mysql").alias("INSTANCE")
        )
    
    def profile_undue_table_privileges(self) -> pl.DataFrame:
        return pl.read_database(
            """
            select grantee as `PROFILE`,`TABLE_SCHEMA`,`TABLE_NAME`,
            group_concat(privilege_type separator ' | ') as `PRIVILEGE`
            from (
                select grantee,table_schema,table_name,privilege_type 
                from information_schema.tables
                inner join information_schema.schema_privileges sp using (table_schema)
                where table_schema not in ('sys','information_schema','mysql','performance_schema')
                and trim('''' from substring_index(grantee,'@',1)) != table_schema
                and privilege_type not in (
                    'SELECT','REFERENCES','CREATE TEMPORARY TABLES','LOCK TABLES',
                    'EXECUTE','SHOW VIEW','CREATE ROUTINE','ALTER ROUTINE','EVENT'
                )
                and grantee not in (
                    select grantee from information_schema.user_privileges where privilege_type='SUPER'
                )
                union
                select grantee,table_schema,table_name,privilege_type from information_schema.table_privileges
                where table_schema not in ('sys','information_schema','mysql','performance_schema')
                and trim('''' from substring_index(grantee,'@',1)) != table_schema
                and privilege_type not in ('SELECT','REFERENCES','SHOW VIEW')
                and grantee not in (
                    select grantee from information_schema.user_privileges where privilege_type='SUPER'
                )
            ) privs
            group by grantee,table_schema,table_name
            """
            if self._verno<8 else
            """
            with cte_privilege as (
                select grantee,table_schema,table_name,privilege_type 
                from information_schema.tables
                inner join information_schema.schema_privileges using (table_schema)
                where table_schema not in ('sys','information_schema','mysql','performance_schema')
                and trim('''' from substring_index(grantee,'@',1)) != table_schema
                and privilege_type not in (
                    'SELECT','REFERENCES','CREATE TEMPORARY TABLES','LOCK TABLES',
                    'EXECUTE','SHOW VIEW','CREATE ROUTINE','ALTER ROUTINE','EVENT'
                )
                and grantee not in (
                    select grantee from information_schema.user_privileges where privilege_type='SUPER'
                )
                union
                select grantee,table_schema,table_name,privilege_type from information_schema.table_privileges
                where table_schema not in ('sys','information_schema','mysql','performance_schema')
                and trim('''' from substring_index(grantee,'@',1)) != table_schema
                and privilege_type not in ('SELECT','REFERENCES','SHOW VIEW')
                and grantee not in (
                    select grantee from information_schema.user_privileges where privilege_type='SUPER'
                )
            ),
            cte_final as (
                select grantee,table_schema,table_name,privilege_type from cte_privilege
                union
                select concat('''',to_user,'''','@','''',to_host,'''') as grantee,p.table_schema,p.table_name,p.privilege_type
                from mysql.role_edges 
                join cte_privilege p on p.grantee=concat('''',from_user,'''','@','''',from_host,'''')
            )
            select grantee as `PROFILE`,`TABLE_SCHEMA`,`TABLE_NAME`,
            group_concat(privilege_type separator ' | ') as `PRIVILEGE`
            from cte_final
            group by grantee,table_schema,table_name
            """,
            self._conx
        ).with_columns(
            pl.lit(self._socket).alias("SOCKET"),
            pl.lit("mysql").alias("INSTANCE")
        )
        

    def role_without_members(self) -> pl.DataFrame:
        if self._verno<8:
            raise NotImplementedError("Only MySQL version >= 8 implemets role")
        
        return pl.read_database(
            """
            select concat('''',user,'''','@','''',host,'''') as `ROLE` from mysql.user
            where password_expired='Y' and account_locked='Y' and not length(authentication_string)
            and concat('''',user,'''','@','''',host,'''') not in (
                select concat('''',from_user,'''','@','''',from_host,'''')
                from mysql.role_edges
            )
            """,
            self._conx
        ).with_columns(
            pl.lit(self._socket).alias("SOCKET"),
            pl.lit("mysql").alias("INSTANCE")
        )
