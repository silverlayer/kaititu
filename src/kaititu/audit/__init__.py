from abc import ABC, abstractmethod
from polars import DataFrame
from sqlalchemy.engine import Connection

class AccessControlReport(ABC):
    """
    Abstract class for access control reports.
    Throughout this entity, the term **Profile** refers to users or roles interchangeably.
    """
    def __init__(self, conx: Connection) -> None:
        super().__init__()
        self._conx=conx
        self._socket=conx.info["socket"]
        self._instance=conx.info["instance"]

    @staticmethod
    def _check_connection_type(conx: Connection) -> None:
        if not isinstance(conx,Connection):
            raise TypeError("conx must be an instance of sqlalchemy.engine.Connection")
         
    @abstractmethod
    def profile_with_login(self) -> DataFrame:
        """
        Get users or roles that can connect (login)

        Returns:
            DataFrame: a 3-columns dataframe as below

            **PROFILE** => Role name or User name

            **INSTANCE** => Database name or Service name

            **SOCKET** => Database Host and port as string
        """
        pass
    
    @abstractmethod
    def role_without_members(self) -> DataFrame:
        """
        Get roles without members

        Returns:
            DataFrame: 3-columns dataframe with roles that don't have members

            **ROLE** => Role name

            **INSTANCE** => Database name or Service name

            **SOCKET** => Database Host and port as string
        """
        pass

    @abstractmethod
    def profile_undue_table_privileges(self) -> DataFrame:
        """
        Get undue privileges for tables per profile if any.
        Undue privilege for tables happens when a profile isn't owner of a table and can do any DML or DDL operation on it, except select.

        Returns:
            DataFrame: 6-columns dataframe with undue privileges per role

            **PROFILE** => Role name or User name

            **TABLE_SCHEMA** => The schema's name of tables

            **TABLE_NAME** => The name of table

            **PRIVILEGE** => All role's privilege separated by '|'. eg. "INSERT | UPDATE | GRANT"

            **INSTANCE** => Database name or Service name

            **SOCKET** => Database Host and port as string
        """
        pass