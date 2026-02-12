import unittest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from plume.core import NostrFileAuthenticityTool
import electrum_ecc as ecc
from electrum_aionostr.event import Event

class TestNostrFileAuthenticityTool(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    @patch('plume.core.aionostr.Manager')
    def test_publish_signature(self, mock_manager_cls):
        # Setup mock manager
        mock_manager = AsyncMock()
        mock_manager.relays = ['wss://relay.example.com']
        mock_manager.add_event.return_value = "event_id_123"
        mock_manager_cls.return_value.__aenter__.return_value = mock_manager

        # Test data
        file_hash = b'a' * 32
        priv_key = b'b' * 32
        relays = {'wss://relay.example.com'}

        # Run test
        self.loop.run_until_complete(
            NostrFileAuthenticityTool.publish_signature(
                file_hash_sha256=file_hash,
                private_key=priv_key,
                nostr_relays=relays,
                proxy=None
            )
        )

        # Verify
        mock_manager.add_event.assert_called_once()
        call_args = mock_manager.add_event.call_args
        event = call_args[0][0]
        self.assertIsInstance(event, Event)
        self.assertEqual(event.kind, NostrFileAuthenticityTool.NOSTR_EVENT_KIND)
        self.assertTrue(any(t[0] == 'd' and t[1].startswith(file_hash.hex()) for t in event.tags))

    @patch('plume.core.aionostr.Manager')
    def test_verify_hash(self, mock_manager_cls):
        # Setup mock manager
        mock_manager = AsyncMock()
        mock_manager.relays = ['wss://relay.example.com']

        # Create a valid event
        priv_key = ecc.ECPrivkey(b'b' * 32)
        pub_key_hex = priv_key.get_public_key_hex()[2:]
        file_hash = b'a' * 32
        tags = [['d', f"{file_hash.hex()}:{NostrFileAuthenticityTool.SIGNING_PROTOCOL_VERSION}"]]
        event = Event(
            pubkey=pub_key_hex,
            kind=NostrFileAuthenticityTool.NOSTR_EVENT_KIND,
            content="",
            tags=tags,
        )
        event = event.sign(priv_key.get_secret_bytes().hex())
        assert isinstance(event, Event)

        # Mock get_events to yield our event
        async def mock_get_events(*args, **kwargs):
            yield event

        mock_manager.get_events = mock_get_events
        mock_manager_cls.return_value.__aenter__.return_value = mock_manager

        # Test data
        trusted_pubkeys = {pub_key_hex}
        relays = {'wss://relay.example.com'}

        # Run test
        async def run_verify():
            found_pubkeys = []
            async for pk in NostrFileAuthenticityTool.verify_hash(
                file_hash_sha256=file_hash,
                trusted_signing_pubkeys_hex=trusted_pubkeys,
                timeout_sec=5,
                nostr_relays=relays,
                proxy=None
            ):
                found_pubkeys.append(pk)
            return found_pubkeys

        found = self.loop.run_until_complete(run_verify())

        # Verify
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0], pub_key_hex)

if __name__ == '__main__':
    unittest.main()
