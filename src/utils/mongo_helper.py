from __future__ import annotations

import logging

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import PyMongoError


class MongoHelper:
    """
        This is a helper class to run MongoDB operations such as get, create, insert, update, delete collection
    """
    def __init__(self, credentials: dict[str, str]):
        """
            This is a constructor that initializes MongoDB connection
        """
        self._credentials = credentials
        self._client = self._establish_connection()

    def _establish_connection(self) -> MongoClient:
        """
            This method will establish a mongodb connection and returns the connected client
        """
        username = self._credentials['username']
        password = self._credentials['password']
        cluster_id = self._credentials['cluster_id']
        try:
            return MongoClient(f"mongodb+srv://{username}:{password}@{cluster_id}")
        except PyMongoError as pme:
            raise pme

    def list_databases(self) -> list[dict]:
        """
            This method will list all databases in the mongodb
        """
        return [db for db in self._client.list_databases()]

    def _get_database(self, database: str) -> Database:
        """
            This method will get the database client using the database name
        """
        return self._client.get_database(database)

    def _get_collection(self, database: str, collection: str) -> Collection:
        """
            This method will get the collection client using the database and the collection name
        """
        self.create_collection(database, collection)
        return self._get_database(database).get_collection(collection)

    def create_collection(self, database: str, collection: str) -> None:
        """
            This method will create the collection in the given database
        """
        db = self._get_database(database)
        if collection not in db.list_collection_names():
            db.create_collection(collection)

    def insert_doc(self, database: str, collection: str, record: dict[str, any]) -> None:
        """
            This method will insert/update the document in the collection of the database
        """
        if '_id' not in record:
            logging.warning(f'_id not set for {database}.{collection}')

        collection = self._get_collection(database, collection)
        collection.replace_one({"_id": record["_id"]}, record, upsert=True)

    def insert_docs(self, database: str, collection: str, records: list[dict[str, any]]) -> None:
        """
            This method will insert/update the documents in the collection of the database
        """
        collection = self._get_collection(database, collection)
        collection.insert_many(records)

    def get_doc(self, database: str, collection: str, query: dict[str, any]) -> dict[str, any] | None:
        """
            This method will get the document in the collection of the database
        """
        collection = self._get_collection(database, collection)
        return collection.find_one(query)

    def get_docs(self, database: str, collection: str, query: dict[str, any]) -> list[dict[str, any]]:
        """
            This method will get the documents in the collection of the database
        """
        collection = self._get_collection(database, collection)
        return list(collection.find(query))

    def delete_doc(self, database: str, collection: str, query: dict[str, any]) -> None:
        """
            This method will delete the document in the collection of the database
        """
        collection = self._get_collection(database, collection)
        collection.delete_one(query)

    def close(self):
        """
            This method will close the connection to MongoDB
        """
        self._client.close()


