from kaititu.audit import AccessControlReport
from kaititu import MSSql
import polars as pl

class MSSqlACR(AccessControlReport):
    """
    MS SQL Server access control report. Tested on SQL Server version >= 2012
    

    Note:
        The **INSTANCE** column is the database where the queries are executed.
    """

    def __init__(self, instance: MSSql) -> None:
        """
        Initializer

        Args:
            instance (MSSql): MSSql database instance

        Raises:
            TypeError: if **instance** is not a class or subclass of :class:`kaititu.MSSql`
        """
        if not isinstance(instance,MSSql):
            raise TypeError("provide an instance of MSSql class")
        
        super().__init__(instance)


    def profile_undue_table_privileges(self) -> pl.DataFrame:
        all_dfs = self._db.multi_qry(
            # fixed role db_owner
            """
            with cte_profile as (
                select u.name as PROFILE, u.type_desc
                from sys.database_role_members rm
                inner join sys.database_principals u on (rm.member_principal_id=u.principal_id)
                where rm.role_principal_id=user_id('db_owner')
                and u.name!=db_name()
            ),
            cte_tables as (
                select s.name as TABLE_SCHEMA,t.name as TABLE_NAME
                from sys.tables t
                inner join sys.schemas s on (t.schema_id=s.schema_id)
            ),
            cte_privs(PRIVILEGE) as (
                select 'INSERT' union select 'UPDATE' union
                select 'DELETE' union select 'ALTER' union
                select 'DROP' union select 'TRUNCATE' union
                select 'GRANT' union select 'DENY' union
                select 'REVOKE'
            )
            select concat(PROFILE collate database_default,' (',type_desc collate database_default,')') as PROFILE,
            TABLE_SCHEMA,TABLE_NAME,PRIVILEGE  
            from cte_profile
            cross join cte_tables
            cross join cte_privs
            where PROFILE!=TABLE_SCHEMA
            and PROFILE not in (
                select u.name collate database_default from sys.server_role_members rm
                inner join sys.server_principals r on (rm.role_principal_id=r.principal_id)
                inner join sys.server_principals u on (rm.member_principal_id=u.principal_id)
                where r.name='sysadmin'
            )
            """,
            # fixed role db_ddladmin
            """
            with cte_profile as (
                select u.name as PROFILE, u.type_desc
                from sys.database_role_members rm
                inner join sys.database_principals u on (rm.member_principal_id=u.principal_id)
                where rm.role_principal_id=user_id('db_ddladmin')
                and u.name!=db_name()
            ),
            cte_tables as (
                select s.name as TABLE_SCHEMA,t.name as TABLE_NAME
                from sys.tables t
                inner join sys.schemas s on (t.schema_id=s.schema_id)
            ),
            cte_privs(PRIVILEGE) as (
                select 'ALTER' union select 'DROP' union select 'TRUNCATE'
            )
            select concat(PROFILE collate database_default,' (',type_desc collate database_default,')') as PROFILE,
            TABLE_SCHEMA,TABLE_NAME,PRIVILEGE  
            from cte_profile
            cross join cte_tables
            cross join cte_privs
            where PROFILE!=TABLE_SCHEMA
            and PROFILE not in (
                select u.name collate database_default from sys.server_role_members rm
                inner join sys.server_principals r on (rm.role_principal_id=r.principal_id)
                inner join sys.server_principals u on (rm.member_principal_id=u.principal_id)
                where r.name='sysadmin'
            )
            """,
            # fixed role db_datawriter
            """
            with cte_profile as (
                select u.name as PROFILE, u.type_desc
                from sys.database_role_members rm
                inner join sys.database_principals u on (rm.member_principal_id=u.principal_id)
                where rm.role_principal_id=user_id('db_datawriter')
                and u.name!=db_name()
            ),
            cte_tables as (
                select s.name as TABLE_SCHEMA,t.name as TABLE_NAME
                from sys.tables t
                inner join sys.schemas s on (t.schema_id=s.schema_id)
            ),
            cte_privs(PRIVILEGE) as (
                select 'INSERT' union select 'UPDATE' union select 'DELETE'
            )
            select concat(PROFILE collate database_default,' (',type_desc collate database_default,')') as PROFILE,
            TABLE_SCHEMA,TABLE_NAME,PRIVILEGE  
            from cte_profile
            cross join cte_tables
            cross join cte_privs
            where PROFILE!=TABLE_SCHEMA
            and PROFILE not in (
                select u.name collate database_default from sys.server_role_members rm
                inner join sys.server_principals r on (rm.role_principal_id=r.principal_id)
                inner join sys.server_principals u on (rm.member_principal_id=u.principal_id)
                where r.name='sysadmin'
            )
            """,
            # fixed role db_securityadmin
            """
            with cte_profile as (
                select u.name as PROFILE, u.type_desc
                from sys.database_role_members rm
                inner join sys.database_principals u on (rm.member_principal_id=u.principal_id)
                where rm.role_principal_id=user_id('db_securityadmin')
                and u.name!=db_name()
            ),
            cte_tables as (
                select s.name as TABLE_SCHEMA,t.name as TABLE_NAME
                from sys.tables t
                inner join sys.schemas s on (t.schema_id=s.schema_id)
            ),
            cte_privs(PRIVILEGE) as (
                select 'GRANT' union select 'DENY' union select 'REVOKE'
            )
            select concat(PROFILE collate database_default,' (',type_desc collate database_default,')') as PROFILE,
            TABLE_SCHEMA,TABLE_NAME,PRIVILEGE  
            from cte_profile
            cross join cte_tables
            cross join cte_privs
            where PROFILE!=TABLE_SCHEMA
            and PROFILE not in (
                select u.name collate database_default from sys.server_role_members rm
                inner join sys.server_principals r on (rm.role_principal_id=r.principal_id)
                inner join sys.server_principals u on (rm.member_principal_id=u.principal_id)
                where r.name='sysadmin'
            )
            """,
            # privileges granted directly on tables to users
            """
            select dp.name as PROFILE,s.name as TABLE_SCHEMA,o.name as TABLE_NAME,perm.permission_name as PRIVILEGE
            from sys.database_permissions perm
            inner join sys.objects o on (perm.major_id=o.object_id)
            inner join sys.schemas s on (o.schema_id=s.schema_id)
            inner join sys.database_principals dp on (perm.grantee_principal_id=dp.principal_id)
            where perm.permission_name not in ('SELECT','REFERENCES')
            and o.type='U' and dp.name!=s.name
            and dp.name collate database_default not in (
                select u.name collate database_default from sys.server_role_members rm
                inner join sys.server_principals r on (rm.role_principal_id=r.principal_id)
                inner join sys.server_principals u on (rm.member_principal_id=u.principal_id)
                where r.name='sysadmin'
            )
            """
        )

        df=pl.concat(all_dfs, how="vertical").unique().group_by("PROFILE","TABLE_SCHEMA","TABLE_NAME").agg("PRIVILEGE")
        
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
        # template query
        return self._db.single_qry(
            """
            select concat(r.name collate database_default,iif(r.is_fixed_role>0,' (FIXED_ROLE)','')) as ROLE
            from sys.database_principals r
            left join sys.database_role_members rm on (r.principal_id=rm.role_principal_id)
            where r.type='R' and r.name!='public'
            and rm.member_principal_id is null
            """
        ).with_columns(
            pl.lit(self._db.socket).alias("SOCKET"),
            pl.lit(self._db.instance).alias("INSTANCE")
        )
    

    def profile_with_login(self) -> pl.DataFrame:
        return self._db.single_qry(
            """
            select concat(sp.name collate database_default ,' (',sp.type_desc collate database_default,')') as PROFILE
            from master.sys.server_principals sp
            join sys.database_principals dp on (sp.sid=dp.sid)
            where sp.type in ('S','U','G') and sp.is_disabled=0
            """
        ).with_columns(
            pl.lit(self._db.socket).alias("SOCKET"),
            pl.lit(self._db.instance).alias("INSTANCE")
        )