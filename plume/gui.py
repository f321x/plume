import asyncio
import json
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
from typing import Optional, Dict, Any
import logging
import os
import platformdirs

from electrum_aionostr.key import PrivateKey as NostrPrivateKey
from electrum_aionostr.key import PublicKey as NostrPublicKey
from electrum_aionostr.util import normalize_url
from aiohttp_socks import ProxyConnector

from .core import NostrFileAuthenticityTool
from .config import save_user_config, load_user_config, get_default_relays, get_default_trusted_npubs

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AuthenticityToolApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Plume - Nostr File Authenticity Tool")
        self.geometry("600x450")

        try:
            icon_path = os.path.join(os.path.dirname(__file__), 'icon.png')
            self.icon_img = tk.PhotoImage(file=icon_path)
            self.iconphoto(True, self.icon_img)
        except Exception as e:
            logger.warning(f"Could not load icon: {e}")

        self.config_data = load_user_config()
        self.trusted_npubs = set(self.config_data.get("trusted_npubs", get_default_trusted_npubs()))
        self.relays = set(self.config_data.get("relays", get_default_relays()))
        self.proxy_url = self.config_data.get("proxy_url", "")
        self.min_sigs = 2

        self.create_widgets()

        # Start asyncio loop in a separate thread
        self.loop = asyncio.new_event_loop()
        self.loop_thread = threading.Thread(target=self.start_loop, daemon=True)
        self.loop_thread.start()

    def start_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def save_config(self):
        data = {
            "trusted_npubs": list(self.trusted_npubs),
            "relays": list(self.relays),
            "proxy_url": self.proxy_url
        }
        try:
            save_user_config(data)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {e}")

    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Menu Bar
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Configure Trusted Pubkeys", command=self.configure_trusted_pubkeys)
        tools_menu.add_command(label="Configure Relays", command=self.configure_relays)
        tools_menu.add_command(label="Configure Proxy", command=self.configure_proxy)
        tools_menu.add_separator()
        tools_menu.add_command(label="Sign File", command=self.sign_file_dialog)

        # Description
        ttk.Label(main_frame, text="Select a file you want to verify against your trusted signers.", wraplength=580).pack(pady=10)

        # File Selection
        self.select_file_btn = ttk.Button(main_frame, text="Select File to Verify", command=self.verify_file)
        self.select_file_btn.pack(pady=5)

        self.file_label = ttk.Label(main_frame, text="", wraplength=580)
        self.file_label.pack(pady=5)

        # Status
        self.status_label = ttk.Label(main_frame, text="", font=("Helvetica", 12))
        self.status_label.pack(pady=10)

    def configure_trusted_pubkeys(self):
        dialog = tk.Toplevel(self)
        dialog.title("Configure Trusted Pubkeys")
        dialog.geometry("500x400")
        dialog.transient(self)
        dialog.grab_set()

        ttk.Label(dialog, text="Trusted public keys (npubs):").pack(pady=5)

        text_area = tk.Text(dialog, height=15, width=60)
        text_area.pack(pady=5, padx=10)
        text_area.insert(tk.END, '\n'.join(sorted(list(self.trusted_npubs))))

        def save():
            content = text_area.get("1.0", tk.END).strip()
            if not content:
                self.trusted_npubs = set()
            else:
                npubs = set(content.split())
                valid_npubs = set()
                for npub in npubs:
                    try:
                        NostrPublicKey.from_npub(npub)
                        valid_npubs.add(npub)
                    except Exception:
                        messagebox.showerror("Error", f"Invalid pubkey: {npub}", parent=dialog)
                        return
                self.trusted_npubs = valid_npubs
            self.save_config()
            dialog.destroy()

        def restore_defaults():
            text_area.delete("1.0", tk.END)
            text_area.insert(tk.END, '\n'.join(sorted(list(get_default_trusted_npubs()))))

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Restore Defaults", command=restore_defaults).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save", command=save).pack(side=tk.LEFT, padx=5)

    def configure_relays(self):
        dialog = tk.Toplevel(self)
        dialog.title("Configure Relays")
        dialog.geometry("500x400")
        dialog.transient(self)
        dialog.grab_set()

        ttk.Label(dialog, text="Nostr Relays:").pack(pady=5)

        text_area = tk.Text(dialog, height=15, width=60)
        text_area.pack(pady=5, padx=10)
        text_area.insert(tk.END, '\n'.join(sorted(list(self.relays))))

        def save():
            content = text_area.get("1.0", tk.END).strip()
            if not content:
                self.relays = set()
            else:
                self.relays = set([normalize_url(u) for u in content.split()])
            self.save_config()
            dialog.destroy()

        def restore_defaults():
            text_area.delete("1.0", tk.END)
            text_area.insert(tk.END, '\n'.join(sorted(list(get_default_relays()))))

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Restore Defaults", command=restore_defaults).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save", command=save).pack(side=tk.LEFT, padx=5)

    def configure_proxy(self):
        dialog = tk.Toplevel(self)
        dialog.title("Configure Proxy")
        dialog.geometry("400x150")
        dialog.transient(self)
        dialog.grab_set()

        ttk.Label(dialog, text="Proxy URL (e.g. socks5://user:pass@host:port):").pack(pady=5)

        proxy_entry = ttk.Entry(dialog, width=50)
        proxy_entry.pack(pady=5, padx=10)
        proxy_entry.insert(0, self.proxy_url)

        def save():
            self.proxy_url = proxy_entry.get().strip()
            if not self.get_proxy_connector():
                messagebox.showerror("Error", f"Invalid proxy url: {self.proxy_url}", parent=dialog)
                self.proxy_url = ""
                return
            dialog.destroy()
            self.save_config()

        ttk.Button(dialog, text="Save", command=save).pack(pady=10)

    def get_proxy_connector(self) -> Optional[ProxyConnector]:
        if self.proxy_url:
            try:
                return ProxyConnector.from_url(self.proxy_url)
            except Exception as e:
                logger.error(f"Invalid proxy URL: {e}")
                return None
        return None

    def sign_file_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Sign File")
        dialog.geometry("500x250")
        dialog.transient(self)
        dialog.grab_set()

        # File selection
        file_frame = ttk.Frame(dialog)
        file_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(file_frame, text="File:").pack(side=tk.LEFT)
        file_entry = ttk.Entry(file_frame)
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        def browse_file():
            filename = filedialog.askopenfilename(parent=dialog)
            if filename:
                file_entry.delete(0, tk.END)
                file_entry.insert(0, filename)

        ttk.Button(file_frame, text="...", command=browse_file).pack(side=tk.LEFT)

        # Private Key
        key_frame = ttk.Frame(dialog)
        key_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(key_frame, text="Nostr Private Key (nsec):").pack(side=tk.LEFT)
        key_entry = ttk.Entry(key_frame, show="*")
        key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        def sign():
            filename = file_entry.get()
            nsec = key_entry.get()

            if not filename:
                messagebox.showerror("Error", "Please select a file", parent=dialog)
                return

            try:
                nostr_privkey = NostrPrivateKey.from_nsec(nsec)
            except Exception:
                messagebox.showerror("Error", "Invalid private key", parent=dialog)
                return

            try:
                with open(filename, 'rb') as f:
                    file_content = f.read()
                file_hash = hashlib.sha256(file_content).digest()
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=dialog)
                return

            if not self.relays:
                messagebox.showerror("Error", "No relays configured", parent=dialog)
                return

            # Disable button
            sign_btn.state(['disabled'])

            async def sign_coro():
                try:
                    proxy = self.get_proxy_connector()
                    await NostrFileAuthenticityTool.publish_signature(
                        file_hash_sha256=file_hash,
                        private_key=nostr_privkey.raw_secret,
                        nostr_relays=self.relays,
                        proxy=proxy,
                    )
                    self.after(0, lambda: messagebox.showinfo("Success", "Signature published successfully"))
                    self.after(0, dialog.destroy)
                except Exception as e:
                    logger.exception("Error signing file")
                    self.after(0, lambda: sign_btn.state(['!disabled']))
                    self.after(0, lambda: messagebox.showerror("Error", str(e), parent=dialog))

            asyncio.run_coroutine_threadsafe(sign_coro(), self.loop)

        sign_btn = ttk.Button(dialog, text="Sign and Publish", command=sign)
        sign_btn.pack(pady=20)

    def verify_file(self):
        filename = filedialog.askopenfilename()
        if not filename:
            return

        if not self.trusted_npubs:
            self.status_label.config(text="Error: No trusted pubkeys configured", foreground="red")
            return

        self.file_label.config(text=filename)
        self.status_label.config(text="Hashing file...", foreground="black")
        self.select_file_btn.state(['disabled'])
        self.update()

        try:
            with open(filename, 'rb') as f:
                file_content = f.read()
            file_hash = hashlib.sha256(file_content).digest()
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}", foreground="red")
            self.select_file_btn.state(['!disabled'])
            return

        trusted_pubkeys = set(NostrPublicKey.from_npub(npub).hex() for npub in self.trusted_npubs)

        self.status_label.config(text="Verifying...", foreground="black")

        async def verify_coro():
            try:
                proxy = self.get_proxy_connector()
                found_signers = set()
                async for signer_pubkey in NostrFileAuthenticityTool.verify_hash(
                    file_hash_sha256=file_hash,
                    trusted_signing_pubkeys_hex=trusted_pubkeys,
                    timeout_sec=20,
                    nostr_relays=self.relays,
                    proxy=proxy,
                ):
                    if signer_pubkey not in found_signers:
                        found_signers.add(signer_pubkey)
                        self.after(0, lambda n=len(found_signers): self.status_label.config(
                            text=f"Found {n} signature(s)..."
                        ))

                        if len(found_signers) >= self.min_sigs or len(found_signers) >= len(trusted_pubkeys):
                            break

                def finish():
                    if len(found_signers) >= self.min_sigs or (trusted_pubkeys and len(found_signers) >= len(trusted_pubkeys)):
                        self.status_label.config(
                            text=f"File Authentic. Found {len(found_signers)} signatures.",
                            foreground="green"
                        )
                    else:
                        self.status_label.config(
                            text=f"Verification failed. Found {len(found_signers)} signatures.",
                            foreground="red"
                        )
                    self.select_file_btn.state(['!disabled'])

                self.after(0, finish)

            except Exception as e:
                logger.exception("Error verifying file")
                self.after(0, lambda: self.status_label.config(text=f"Error: {str(e)}", foreground="red"))
                self.after(0, lambda: self.select_file_btn.state(['!disabled']))

        asyncio.run_coroutine_threadsafe(verify_coro(), self.loop)

def main():
    app = AuthenticityToolApp()
    app.mainloop()

if __name__ == "__main__":
    main()
