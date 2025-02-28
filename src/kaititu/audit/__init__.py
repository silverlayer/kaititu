from abc import ABC, abstractmethod
from polars import DataFrame
from kaititu import Database

class AccessControlReport(ABC):
    """
    Abstract class for access control reports.
    All method here returns the columns **INSTANCE** and **HOST** besides the other columns into a :class:`polars.DataFrame`

    Note:
        Throughout this entity, the term **Profile** refers to users or roles interchangeably.
    """
    def __init__(self, instance: Database) -> None:
        """
        Initializer of abstract class

        Args:
            instance (Database): a subclass of :class:`kaititu.Database`
        """
        super().__init__()
        self._db = instance
        
    
    @property
    def db(self) -> Database:
        """
        Get the current database object

        Returns:
            Database: an instance of Database
        """
        return self._db
     
    @abstractmethod
    def profile_with_login(self) -> DataFrame:
        """
        Get users or roles that can connect (login)

        Returns:
            DataFrame: 3-columns dataframe with profiles that have login privilege
        """
        pass
    
    @abstractmethod
    def role_without_members(self) -> DataFrame:
        """
        Get roles without members

        Returns:
            DataFrame: 3-columns dataframe with roles that don't have members
        """
        pass

    @abstractmethod
    def profile_undue_table_privileges(self) -> DataFrame:
        """
        Get undue privileges for tables per profile if any.
        Undue privilege for tables happens when a profile isn't owner of a table and can do any DML or DDL operation on it, except select.

        Returns:
            DataFrame: 6-columns dataframe with undue privileges per role.
        """
        pass