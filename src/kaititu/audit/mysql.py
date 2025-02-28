from kaititu.audit import AccessControlReport
from kaititu import MySql
import polars as pl
import re

class MySqlACR(AccessControlReport):
    """
    MySQL access control report. Tested on MySQL version >= 5.

    Note:
        For MySQL, the **INSTANCE** column is always 'mysql', no matter which database is chosen. 
    """
    def __init__(self, instance: MySql) -> None:
        """
        Initializer

        Args:
            instance (MySql): database instance

        Raises:
            TypeError: if **instance** is not a class or subclass of :class:`kaititu.MySql`
        """
        if not isinstance(instance,MySql):
            raise TypeError("provide an instance of MySql class")
        
        super().__init__(instance)
        # major version number
        ver=re.search(r"(\d+)\.\d+\.\d+",instance.version)
        if not ver: raise ValueError("Invalid MySQL host: "+instance.version)
        self._verno=int(ver.group(1))

    def profile_with_login(self) -> pl.DataFrame:
        return self._db.single_qry(
            """select distinct replace(grantee,'''','') as `PROFILE` from information_schema.USER_PRIVILEGES"""\
            if self._verno<8 else\
            """
            select concat('''',user,'''','@','''',host,'''') as `PROFILE` from mysql.user
            where password_expired='N' and account_locked='N' and length(authentication_string)>0
            """
        ).with_columns(
            pl.lit(self._db.host).alias("HOST"),
            pl.lit("mysql").alias("INSTANCE")
        )
    
    def profile_undue_table_privileges(self) -> pl.DataFrame:
        return self._db.single_qry(
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
            """
        ).with_columns(
            pl.lit(self._db.host).alias("HOST"),
            pl.lit("mysql").alias("INSTANCE")
        )
        

    def role_without_members(self) -> pl.DataFrame:
        if self._verno<8:
            raise NotImplementedError("Only MySQL version >= 8 implemets role")
        
        return self._db.single_qry(
            """
            select concat('''',user,'''','@','''',host,'''') as `ROLE` from mysql.user
            where password_expired='Y' and account_locked='Y' and not length(authentication_string)
            and concat('''',user,'''','@','''',host,'''') not in (
                select concat('''',from_user,'''','@','''',from_host,'''')
                from mysql.role_edges
            )
            """
        ).with_columns(
            pl.lit(self._db.host).alias("HOST"),
            pl.lit("mysql").alias("INSTANCE")
        )
