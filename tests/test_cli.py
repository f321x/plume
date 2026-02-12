import unittest
import argparse
import asyncio
import os
import json
import tempfile
import shutil
from unittest.mock import MagicMock, patch, AsyncMock
from plume import cli
from plume import config

class TestCLI(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.config_dir = os.path.join(self.test_dir, "config")
        os.makedirs(self.config_dir)
        
        # Patch platformdirs to use our temp directory
        self.patcher_config = patch('plume.config.platformdirs.user_config_dir', return_value=self.config_dir)
        self.mock_config_dir = self.patcher_config.start()

        # Create a dummy file for signing/verifying
        self.test_file = os.path.join(self.test_dir, "test.txt")
        with open(self.test_file, "wb") as f:
            f.write(b"test content")

    def tearDown(self):
        self.patcher_config.stop()
        shutil.rmtree(self.test_dir)

    def test_calculate_file_hash(self):
        # sha256 of "test content"
        expected_hash = bytes.fromhex("6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72")
        self.assertEqual(cli.calculate_file_hash(self.test_file), expected_hash)

    def test_calculate_file_hash_not_found(self):
        with self.assertRaises(SystemExit):
            with self.assertLogs(level='ERROR'):
                cli.calculate_file_hash("non_existent_file.txt")

    @patch('plume.cli.load_user_config')
    def test_get_relays_default(self, mock_load_config):
        mock_load_config.return_value = {}
        args = argparse.Namespace(relays=None)
        relays = cli.get_relays(args)
        self.assertTrue(len(relays) > 0) # Should have defaults

    @patch('plume.cli.load_user_config')
    def test_get_relays_override(self, mock_load_config):
        mock_load_config.return_value = {}
        args = argparse.Namespace(relays=["wss://override.com"])
        relays = cli.get_relays(args)
        self.assertEqual(relays, {"wss://override.com"})

    @patch('plume.cli.load_user_config')
    def test_get_trusted_pubkeys_default(self, mock_load_config):
        mock_load_config.return_value = {}
        args = argparse.Namespace(trusted_pubkeys=None)
        pubkeys = cli.get_trusted_pubkeys(args)
        self.assertTrue(len(pubkeys) > 0) # Should have defaults

    @patch('plume.cli.load_user_config')
    def test_get_trusted_pubkeys_override(self, mock_load_config):
        mock_load_config.return_value = {}
        args = argparse.Namespace(trusted_pubkeys=["npub1z9n5ktfjrlpyywds9t7ljekr9cm9jjnzs27h702te5fy8p2c4dgs5zvycf"])
        pubkeys = cli.get_trusted_pubkeys(args)
        self.assertEqual(pubkeys, {"11674b2d321fc24239b02afdf966c32e36594a6282bd7f3d4bcd12438558ab51"})

    @patch('plume.cli.NostrFileAuthenticityTool.publish_signature')
    def test_sign_command(self, mock_publish):
        mock_publish.return_value = None

        args = argparse.Namespace(
            file=self.test_file,
            key=os.urandom(32).hex(),
            relays=None,
            proxy=None
        )
        
        asyncio.run(cli.sign_command(args))
        mock_publish.assert_called_once()

    @patch('plume.cli.NostrFileAuthenticityTool.publish_signature')
    def test_sign_command_no_key(self, mock_publish):
        args = argparse.Namespace(
            file=self.test_file,
            key=None,
            relays=None,
            proxy=None
        )
        with self.assertRaises(SystemExit):
            with self.assertLogs(level='ERROR'):
                asyncio.run(cli.sign_command(args))

    @patch('plume.cli.NostrFileAuthenticityTool.verify_hash')
    def test_verify_command_success(self, mock_verify):
        # Mock verify to yield a trusted pubkey
        trusted_pubkey = "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2"
        
        async def mock_verify_gen(*args, **kwargs):
            yield trusted_pubkey

        mock_verify.side_effect = mock_verify_gen

        args = argparse.Namespace(
            file=self.test_file,
            trusted_pubkeys=[trusted_pubkey],
            relays=["wss://relay.example.com"],
            proxy=None,
            min_sigs=1,
            timeout=1
        )

        with self.assertRaises(SystemExit) as cm:
            asyncio.run(cli.verify_command(args))
        self.assertEqual(cm.exception.code, 0)

    @patch('plume.cli.NostrFileAuthenticityTool.verify_hash')
    def test_verify_command_failure(self, mock_verify):
        async def mock_verify_gen(*args, **kwargs):
            if False: yield "nothing"

        mock_verify.side_effect = mock_verify_gen

        args = argparse.Namespace(
            file=self.test_file,
            trusted_pubkeys=["82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2"],
            relays=["wss://relay.example.com"],
            proxy=None,
            min_sigs=1,
            timeout=1
        )

        with self.assertRaises(SystemExit) as cm:
            asyncio.run(cli.verify_command(args))
        self.assertEqual(cm.exception.code, 1)

    def test_config_command_add_relay(self):
        args = argparse.Namespace(
            list=False,
            add_relay="wss://new.relay.com",
            remove_relay=None,
            add_trusted=None,
            remove_trusted=None,
            set_proxy=None,
            unset_proxy=False
        )
        cli.config_command(args)
        
        loaded_config = config.load_user_config()
        self.assertIn("wss://new.relay.com", loaded_config["relays"])

    def test_config_command_set_proxy(self):
        args = argparse.Namespace(
            list=False,
            add_relay=None,
            remove_relay=None,
            add_trusted=None,
            remove_trusted=None,
            set_proxy="socks5://localhost:9050",
            unset_proxy=False
        )
        cli.config_command(args)
        
        loaded_config = config.load_user_config()
        self.assertEqual(loaded_config["proxy_url"], "socks5://localhost:9050")

if __name__ == '__main__':
    unittest.main()
