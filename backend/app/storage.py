from minio import Minio
from minio.error import S3Error
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json
import hashlib
from typing import Dict, Tuple, Optional
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)


class StorageService:
    
    def __init__(self):
        self.client = Minio(
            os.getenv("MINIO_ENDPOINT", "minio:9000"),
            access_key=os.getenv("MINIO_ACCESS_KEY", "minioadmin"),
            secret_key=os.getenv("MINIO_SECRET_KEY", "minioadmin"),
            secure=False
        )
        
        self.bucket_name = os.getenv("MINIO_BUCKET", "securevault-documents")
        self._ensure_bucket_exists()
        
        self.master_key = self._get_master_key()
    
    def _ensure_bucket_exists(self):
        try:
            if not self.client.bucket_exists(self.bucket_name):
                self.client.make_bucket(self.bucket_name)
                logger.info(f"Created bucket: {self.bucket_name}")
            else:
                logger.info(f"Bucket exists: {self.bucket_name}")
        except S3Error as e:
            logger.error(f"Error creating bucket: {e}")
            raise
    
    def _get_master_key(self) -> bytes:
        key_hex = os.getenv("MASTER_ENCRYPTION_KEY")
        if key_hex:
            return bytes.fromhex(key_hex)
        
        logger.warning("⚠️  Using ephemeral encryption key. Set MASTER_ENCRYPTION_KEY in production!")
        return AESGCM.generate_key(bit_length=256)
    
    def calculate_checksum(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()
    
    def encrypt_content(
        self, 
        plaintext: bytes, 
        document_id: str,
        owner_id: str,
        classification: str
    ) -> Tuple[bytes, Dict]:
        data_key = AESGCM.generate_key(bit_length=256)
        
        aad_context = {
            "document_id": document_id,
            "owner_id": owner_id,
            "classification": classification
        }
        aad = json.dumps(aad_context, sort_keys=True).encode('utf-8')
        
        aesgcm = AESGCM(data_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        
        master_aesgcm = AESGCM(self.master_key)
        master_nonce = os.urandom(12)
        encrypted_data_key = master_aesgcm.encrypt(master_nonce, data_key, None)
        
        metadata = {
            "algorithm": "AES-256-GCM",
            "nonce": nonce.hex(),
            "master_nonce": master_nonce.hex(),
            "encrypted_data_key": encrypted_data_key.hex(),
            "aad_context": aad_context
        }
        
        return ciphertext, metadata
    
    def decrypt_content(
        self,
        ciphertext: bytes,
        encryption_metadata: Dict
    ) -> bytes:
        nonce = bytes.fromhex(encryption_metadata["nonce"])
        master_nonce = bytes.fromhex(encryption_metadata["master_nonce"])
        encrypted_data_key = bytes.fromhex(encryption_metadata["encrypted_data_key"])
        aad_context = encryption_metadata["aad_context"]
        
        master_aesgcm = AESGCM(self.master_key)
        data_key = master_aesgcm.decrypt(master_nonce, encrypted_data_key, None)
        
        aesgcm = AESGCM(data_key)
        aad = json.dumps(aad_context, sort_keys=True).encode('utf-8')
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        
        return plaintext
    
    def upload_document(
        self,
        content: bytes,
        document_id: str,
        owner_id: str,
        classification: str,
        original_filename: str,
        encrypt: bool = True
    ) -> Dict:
        checksum = self.calculate_checksum(content)
        
        if encrypt:
            ciphertext, encryption_metadata = self.encrypt_content(
                content, document_id, owner_id, classification
            )
            content_to_store = ciphertext
        else:
            ciphertext = content
            encryption_metadata = None
            content_to_store = content
        
        storage_path = f"{owner_id}/{document_id}/{original_filename}"
        
        try:
            from io import BytesIO
            data = BytesIO(content_to_store)
            
            self.client.put_object(
                bucket_name=self.bucket_name,
                object_name=storage_path,
                data=data,
                length=len(content_to_store),
                content_type="application/octet-stream"
            )
            
            logger.info(f"✓ Uploaded document {document_id} to {storage_path}")
            
            return {
                "storage_path": storage_path,
                "size_bytes": len(content),
                "checksum_sha256": checksum,
                "encrypted": encrypt,
                "encryption_metadata": json.dumps(encryption_metadata) if encryption_metadata else None
            }
            
        except S3Error as e:
            logger.error(f"Error uploading document: {e}")
            raise
    
    def download_document(
        self,
        storage_path: str,
        encryption_metadata: Optional[str] = None
    ) -> bytes:
        try:
            response = self.client.get_object(
                bucket_name=self.bucket_name,
                object_name=storage_path
            )
            
            content = response.read()
            response.close()
            response.release_conn()
            
            if encryption_metadata:
                metadata_dict = json.loads(encryption_metadata)
                content = self.decrypt_content(content, metadata_dict)
            
            logger.info(f"✓ Downloaded document from {storage_path}")
            return content
            
        except S3Error as e:
            logger.error(f"Error downloading document: {e}")
            raise
    
    def delete_document(self, storage_path: str):
        try:
            self.client.remove_object(
                bucket_name=self.bucket_name,
                object_name=storage_path
            )
            logger.info(f"✓ Deleted document from {storage_path}")
        except S3Error as e:
            logger.error(f"Error deleting document: {e}")
            raise
    
    def get_presigned_url(
        self,
        storage_path: str,
        expires: timedelta = timedelta(hours=1)
    ) -> str:
        try:
            url = self.client.presigned_get_object(
                bucket_name=self.bucket_name,
                object_name=storage_path,
                expires=expires
            )
            return url
        except S3Error as e:
            logger.error(f"Error generating presigned URL: {e}")
            raise
    
    def list_user_documents(self, owner_id: str) -> list:
        try:
            objects = self.client.list_objects(
                bucket_name=self.bucket_name,
                prefix=f"{owner_id}/",
                recursive=True
            )
            return [obj.object_name for obj in objects]
        except S3Error as e:
            logger.error(f"Error listing documents: {e}")
            raise


class ElasticsearchLogger:
    
    def __init__(self):
        from elasticsearch import Elasticsearch
        
        self.es = Elasticsearch(
            [os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")],
            basic_auth=(
                os.getenv("ELASTICSEARCH_USER", "elastic"),
                os.getenv("ELASTICSEARCH_PASSWORD", "")
            ) if os.getenv("ELASTICSEARCH_PASSWORD") else None
        )
        
        self.index_prefix = "securevault-logs"
        logger.info("✓ Connected to Elasticsearch")
    
    def log_event(self, audit_log_dict: Dict):
        try:
            from datetime import datetime
            index_name = f"{self.index_prefix}-{datetime.utcnow().strftime('%Y.%m.%d')}"
            
            self.es.index(
                index=index_name,
                document=audit_log_dict
            )
            
        except Exception as e:
            logger.error(f"Error logging to Elasticsearch: {e}")
    
    def search_logs(self, query: Dict, size: int = 100) -> list:
        """
        Search audit logs
        """
        try:
            result = self.es.search(
                index=f"{self.index_prefix}-*",
                body=query,
                size=size
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Error searching Elasticsearch: {e}")
            return []