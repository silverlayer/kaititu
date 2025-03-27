"""
 KAITITU is a library to deal with common tasks on databases.
 It has a generic API that helps on operational and analytical tasks for popular database management system.
"""

from abc import ABC
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine, Connection
import oracledb

__version__="1.0.1"


class Database(ABC):
    """
    Abstract class for any specific vendor database.
    It manages queries to the database.
    """
    def __init__(self, srv: str, prt: int, usr: str, pwd: str, ins: str) -> None:
        """
        Initializer

        The user (**usr**) must have sufficient privileges to read system objects like tables and views.

        Args:
            srv (str): database host (IP/name)
            prt (int): database listen port
            usr (str): username
            pwd (str): username's password
            ins (str): instance (database or service name)
        """
        super().__init__()
        self._usr=usr
        self._pwd=pwd
        self._srv=srv
        self._prt=int(prt)
        self._ins=ins
        self._ver="undefined"
        self._eng: Engine = None
    
    @property
    def host(self) -> str:
        """
        Get the database host

        Returns:
            str: database host (name or IP address)
        """
        return self._srv
    
    @property
    def instance(self) -> str:
        """
        Get the database name (for MSSQL, MySql, postgres and so on) or Service name (for Oracle)

        Returns:
            str: database name or Service name
        """
        return self._ins
    
    @property
    def port(self) -> int:
        """
        Get the database port number

        Returns:
            int: database port number
        """
        return self._prt
    
    @property
    def socket(self) -> str:
        """
        Get the current socket, representing host and port.

        Returns:
            str: a socket - 'host:port'
        """
        return f"{self._srv}:{self._prt}"
    
    @property
    def version(self) -> str:
        """
        Get the database version as a banner

        Returns:
            str: database version (verbose)
        """
        return self._ver
    
    def connect(self) -> Connection:
        """
        Get a connection for database.

        Indeed, it's a wrapper for `connect` method of :class:`sqlalchemy.engine.Engine` class.
        However, it puts the 'version', 'instance' and 'socket' into the `info` property of connection.

        Returns:
            :class:`sqlalchemy.engine.Connection`: connection for database
        """
        self.__check_state()
        conn=self._eng.connect()
        conn.info["version"]=self.version
        conn.info["instance"]=self.instance
        conn.info["socket"]=self.socket
        return conn
    
    def __check_state(self) -> None:
        if not self._eng:
            raise ValueError("There is no sqlalchemy engine valid")

class Postgres(Database):
    def __init__(self, srv: str, prt: int, usr: str, pwd: str, ins: str = "postgres") -> None:
        """
        Initializer

        The user (**usr**) must have sufficient privileges to read system objects like tables and views.

        Args:
            srv (str): database host (IP/name)
            prt (int): database listen port
            usr (str): username
            pwd (str): username's password
            ins (str, optional): database name. Defaults to "postgres".
        """
        super().__init__(srv, prt, usr, pwd, ins)
        self._eng=create_engine(f"postgresql://{usr}:{pwd}@{srv}:{prt}/{ins}")

        with self._eng.connect() as conx:
            self._ver=conx.exec_driver_sql("select version()").scalar()

class Oracle(Database):
    def __init__(self, srv: str, prt: int, usr: str, pwd: str, ins: str) -> None:
        """
        Initializer

        The user (**usr**) must have sufficient privileges to read system objects like tables and views.

        Args:
            srv (str): database host (IP/name)
            prt (int): database listen port
            usr (str): username
            pwd (str): username's password
            ins (str): service name
        """        
        super().__init__(srv, prt, usr, pwd, ins)
        # activate thick mode for compatibility with oracle 10g
        oracledb.init_oracle_client()
        self._eng=create_engine(f"oracle+oracledb://{usr}:{pwd}@{srv}:{prt}/?service_name={ins}")

        with self._eng.connect() as conx:
            rslt=conx.exec_driver_sql(
                """SELECT (SELECT BANNER FROM v$version WHERE banner LIKE 'Oracle%') AS B,VERSION 
                FROM PRODUCT_COMPONENT_VERSION WHERE PRODUCT LIKE 'Oracle%'"""
            ).one()
            
            if int(rslt[1].split('.')[0]) > 12:
                self._ver=conx.exec_driver_sql(
                    """SELECT PRODUCT||' '||VERSION_FULL||' - '||STATUS AS V
                    FROM PRODUCT_COMPONENT_VERSION WHERE PRODUCT LIKE 'Oracle%'"""
                ).scalar()
            else:
                self._ver=rslt[0]

class MySql(Database):
    def __init__(self, srv: str, prt: int, usr: str, pwd: str, ins: str = "mysql") -> None:
        """
        Initializer

        The user (**usr**) must have sufficient privileges to read system objects like tables and views.

        Args:
            srv (str): database host (IP/name)
            prt (int): database listen port
            usr (str): username
            pwd (str): username's password
            ins (str, optional): database name. Defaults to "mysql".
        """
        super().__init__(srv, prt, usr, pwd, ins)
        self._eng=create_engine(f"mysql://{usr}:{pwd}@{srv}:{prt}/{ins}")

        with self._eng.connect() as conx:
            self._ver = conx.exec_driver_sql(
                "select concat('MySQL ',@@version,' (',@@version_compile_os,' ',@@version_compile_machine,')') as banner"
            ).scalar()

class MSSql(Database):
    """
    Allow two ways of authentication, windows authentication and SQL Server authentication.
    """
    def __init__(self, srv: str, prt: int, usr: str = '', pwd: str = '', ins: str = "master") -> None:
        """
        Initializer

        The user (**usr**) must have sufficient privileges to read system objects like tables and views.
        
        Args:
            srv (str): database host (IP/name)
            prt (int): database listen port
            usr (str, optional): username. Defaults to ''.
            pwd (str, optional): username's password. Defaults to ''.
            ins (str, optional): database name. Defaults to "master".

        Note:
            Don't provide **usr** and **pwd** for windows authentication.
        """
        super().__init__(srv,prt,usr,pwd,ins)
        if not (usr and pwd):
            self._eng=create_engine(f"mssql://@{srv}:{prt}/{ins}?trusted_connection=yes&driver=SQL+Server")
        else:
            self._eng=create_engine(f"mssql://{usr}:{pwd}@{srv}:{prt}/{ins}?driver=SQL+Server")

        with self._eng.connect() as conx:
            self._ver=conx.exec_driver_sql(
                "select substring(@@version,1,charindex(char(10),@@version)-2) as banner"
            ).scalar()


__all__ = ["__version__","Database","Postgres","Oracle","MySql","MSSql"]