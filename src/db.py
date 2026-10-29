import os
import logging
from pymongo import MongoClient, ASCENDING
from pymongo.errors import ServerSelectionTimeoutError, ConnectionFailure
from src.config import MONGODB_URI, COLLECTIONS

logger = logging.getLogger(__name__)

_client = None

def _get_mock_client():
    import mongomock
    from mongomock.collection import BulkOperationBuilder
    _orig_add_update = BulkOperationBuilder.add_update
    def _patched_add_update(self, selector, update, multi=False, upsert=False, collation=None, array_filters=None, hint=None, **kwargs):
        return _orig_add_update(self, selector, update, multi=multi, upsert=upsert, collation=collation, array_filters=array_filters, hint=hint)
    BulkOperationBuilder.add_update = _patched_add_update
    return mongomock.MongoClient()

def get_client(uri: str = None) -> MongoClient:
    global _client
    if _client is None:
        if os.getenv("VERCEL") == "1" and "MONGODB_URI" not in os.environ:
            _client = _get_mock_client()
            return _client
        target_uri = uri or MONGODB_URI
        try:
            client = MongoClient(target_uri, serverSelectionTimeoutMS=500)
            client.admin.command("ping")
            _client = client
        except (ServerSelectionTimeoutError, ConnectionFailure, Exception) as e:
            logger.info(f"MongoDB not reachable at {target_uri} ({e}). Falling back to in-memory mongomock.")
            _client = _get_mock_client()
    return _client

def get_db(client: MongoClient = None):
    c = client or get_client()
    # If URI contains DB name, use default database, else fallback to zero_trust_db
    try:
        db = c.get_default_database()
        if db is not None:
            return db
    except Exception:
        pass
    return c["zero_trust_db"]

def setup_db(db=None):
    """
    Sets up required collections, indexes, and $jsonSchema validation rules.
    """
    if db is None:
        db = get_db()

    # Define JSON Schema for normalized_events
    schema = {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["event_id", "source", "source_file", "ts_utc", "identity_key", "action", "raw_hash"],
            "properties": {
                "event_id": {"bsonType": "string"},
                "source": {"enum": ["okta", "cloudtrail", "synthetic"]},
                "source_file": {"bsonType": "string"},
                "record_ref": {"bsonType": ["string", "int", "long"]},
                "ts_utc": {"bsonType": "string"},
                "ts_original_tz": {"bsonType": ["string", "null"]},
                "identity_key": {"bsonType": "string"},
                "principal_raw": {"bsonType": "string"},
                "session_id": {"bsonType": ["string", "null"]},
                "ip": {"bsonType": "string"},
                "geo": {"bsonType": "object"},
                "user_agent": {"bsonType": "string"},
                "action": {"bsonType": "string"},
                "resource": {"bsonType": "string"},
                "outcome": {"bsonType": "string"},
                "privilege_context": {"bsonType": "object"},
                "raw_hash": {"bsonType": "string"},
                "validation": {
                    "bsonType": "object",
                    "required": ["status"],
                    "properties": {
                        "status": {"enum": ["VALID", "INVALID", "QUARANTINED"]},
                        "reasons": {"bsonType": "array", "items": {"bsonType": "string"}}
                    }
                }
            }
        }
    }

    # Create collection with validator or update validator
    existing_cols = db.list_collection_names()
    if COLLECTIONS["normalized_events"] not in existing_cols:
        try:
            db.create_collection(COLLECTIONS["normalized_events"], validator=schema)
        except Exception as e:
            logger.debug(f"Validator bypassed (mongomock/unsupported): {e}")
            db.create_collection(COLLECTIONS["normalized_events"])
    else:
        try:
            db.command("collMod", COLLECTIONS["normalized_events"], validator=schema)
        except Exception as e:
            logger.debug(f"Could not update validator on normalized_events: {e}")

    # Unique index on (source, event_id) to guarantee idempotency
    try:
        db[COLLECTIONS["normalized_events"]].create_index(
            [("source", ASCENDING), ("event_id", ASCENDING)],
            unique=True,
            name="idx_source_event_id_unique"
        )
    except Exception as e:
        logger.debug(f"Index creation note: {e}")

    # Index on identity_key and ts_utc for fast correlation
    try:
        db[COLLECTIONS["normalized_events"]].create_index(
            [("identity_key", ASCENDING), ("ts_utc", ASCENDING)],
            name="idx_identity_ts"
        )
    except Exception as e:
        logger.debug(f"Index creation note: {e}")

    # Unique index on dedupe key for alerts
    try:
        db[COLLECTIONS["alerts"]].create_index(
            [("alert_id", ASCENDING)],
            unique=True,
            name="idx_alert_id_unique"
        )
        db[COLLECTIONS["alerts"]].create_index(
            [("incident_id", ASCENDING)],
            name="idx_alert_incident_id"
        )
    except Exception as e:
        logger.debug(f"Index creation note: {e}")

    # Unique index on incident_id for incident chains
    try:
        db[COLLECTIONS["incident_chains"]].create_index(
            [("incident_id", ASCENDING)],
            unique=True,
            name="idx_incident_chain_unique"
        )
    except Exception as e:
        logger.debug(f"Index creation note: {e}")

    return db
