import base64

# pip install pycryptodome
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import Crypto.Signature.pkcs1_15
import Crypto.Util.Padding

public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuaUO2qem3KZguBJ94L/iSwFPFB+CY9xWjdtZkLJHQyWIzdZBxn4/aoVmUuj0VQ4tIXaOvj+0vDvE6pSuLFfYLwDeON9NqASWtV279E/U5pt/djJylC+JBp/3M5dOvI6G/pRO1DQmtr6CVIYxk9NKTF79jyzyYX+ZLwsVvJRJL8TfzVyQoCAc6NlIhq87//5hroYBAOde5nbabv7cscZEkiq2+RevxJxkn/auLXdAU8wfljTiuzCmtK3cO/pscH9ZCFKPTO6q5kDw08yIC4ZrMGB2tozmoqZUssBpaDQYbiAFKDrSr0F3S2j8Ec8zazfCHPCGeRHlQ/7Ky9L5TMEduwIDAQAB\n-----END PUBLIC KEY-----\n"
license_key = b'{"actor":{"actor_type":"agent","actor_id":"b345fc25-0a80-4df7-b568-407341a25ad2"},"action":"message_create","action_time":"2020-12-04T12:00:31.639Z","data":{"message":{"message_parts":[{"text":{"content":"sdf"}}],"app_id":"25d2f067-ad57-40bc-940d-6923601b2f2e","actor_id":"b345fc25-0a80-4df7-b568-407341a25ad2","id":"392fbccc-b45b-4608-adf7-8c3d74fd4b4d","channel_id":"b9311ae5-514c-482b-a4f0-f3c62c543ce7","conversation_id":"459e2e51-39e4-4910-a063-307c37988da7","interaction_id":"406696773695621-1602046404502","message_type":"normal","actor_type":"agent","created_time":"2020-12-04T12:00:31.593Z","user_id":"c6d43945-cad8-4470-b49d-dd040b69a9f5"}}}'

encoded_license_signature = """EsDUrX6YUU/oJPY0JxSNDG6J5pJfUjbzBrgXltzPn8GfrTFzDqYU/ElBHYA/DbcHT+XOP/uIfCuH/7bmYIe9rJVZbx7KBjeq6gHy1IsKbduiT/BxsG43a/jAqrobs39P4PxKGPh2CvauOKxsPjnY9n8mIOAa4kBZYJAk3b8qEydOO9vPUv4kMRqWuXY1dbtP/Okgy2eewUjGt8sqceUeIC2aJdlzrm6qNmU8TWZxKwzt99vstZd9Zns9GLGHTu8ty5tLfdRqHpHP1kBKsnFfMVFJ5n7QpXHttEAiEpQUpI2dieKVJReeMwk1xjgbmHAHok0UI/htLRn5txwc+WzSzg=="""
license_signature = base64.urlsafe_b64decode(encoded_license_signature)
# Padding: none of these solutions work
# license_signature = Crypto.Util.Padding.pad(license_signature, 8, style='pkcs7')
# license_signature = Crypto.Util.Padding.pad(license_signature, 8, style='iso7816')
# license_signature = Crypto.Util.Padding.pad(license_signature, 8, style='x923')
# Custom zero-padding (doesn't work either)
#license_signature = (8 - len(license_signature) % 8)*bytes([0]) + license_signature
#license_signature = license_signature + (8 - len(license_signature) % 8)*bytes([0])

rsa_public_key = RSA.import_key(public_key)
signature = Crypto.Signature.pkcs1_15.new(rsa_public_key)

license_hash = SHA256.new(data=license_key)
print(signature.verify(license_hash, license_signature))