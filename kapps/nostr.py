# The MIT License (MIT)

# Copyright (c) 2021-2024 Krux contributors

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# pylint: skip-file
import os

# avoids importing from flash VSF
os.chdir("/")

VERSION = "0.1"
NAME = "Nostr"

from krux.pages import Menu, MENU_CONTINUE, MENU_EXIT, LETTERS, ESC_KEY
from krux.pages.login import Login, DIGITS_HEX, DIGITS
from krux.pages.home_pages.home import Home
from krux.krux_settings import t, Settings
from krux.display import (
    STATUS_BAR_HEIGHT,
    FONT_HEIGHT,
    BOTTOM_PROMPT_LINE,
    DEFAULT_PADDING,
)
from krux.themes import theme
from krux.kboard import kboard
from krux.key import Key, TYPE_SINGLESIG
from krux.wallet import Wallet
from krux.settings import MAIN_TXT, ELLIPSIS
from embit import bech32, bip32, bip39
from embit.ec import PrivateKey
from embit.networks import NETWORKS
from binascii import hexlify


NSEC_SIZE = 63
HEX_SIZE = 64

NSEC = "nsec"
PRIV_HEX = "priv-hex"
NPUB = "npub"
PUB_HEX = "pub-hex"
HEX = "hex"
MNEMONIC = "mnemonic"
NIP06_PATH = "m/44h/1237h/0h/0/0"

FILE_SUFFIX = "-nostr"
FILE_EXTENSION = ".txt"

# -------------------


class NostrKey:
    """Store and convert Nostr keys"""

    def __init__(self):
        self.set()

    def set(self, key="", value=None):
        """Set key type and its value"""
        self.key = key
        self.value = value

    def load_nsec(self, nsec: str):
        """Load a key in nsec format"""
        if len(nsec) != NSEC_SIZE:
            raise ValueError("NSEC key must be %d chars!" % NSEC_SIZE)
        _, hrp, _ = bech32.bech32_decode(nsec)
        if hrp != NSEC:
            raise ValueError("Not an nsec key!")
        self.set(NSEC, nsec)

    def load_hex(self, hex: str):
        """Load a key in hex format"""
        if len(hex) != HEX_SIZE:
            raise ValueError("Hex key must be %d chars!" % HEX_SIZE)
        # try decoding
        bytes.fromhex(hex)
        self.set(HEX, hex)

    def load_mnemonic(self, mnemonic: str):
        """Load a mnemonic, will assume it is valid"""
        self.set(MNEMONIC, mnemonic)

    def is_loaded(self):
        """If a key was loaded"""
        return self.key != ""

    def is_mnemonic(self):
        """If loaded key is mnemonic"""
        return self.key == MNEMONIC

    @staticmethod
    def _encode_bech32(data: bytes, version: str):
        """Encode bytes into a bech32 string with given version"""
        converted_data = bech32.convertbits(data, 8, 5)
        return bech32.bech32_encode(bech32.Encoding.BECH32, version, converted_data)

    @staticmethod
    def _decode_bech32(bech: str):
        """Decode a bech32 string returning bytes"""
        _, _, data = bech32.bech32_decode(bech)
        if not data:
            raise ValueError("Invalid bech32 data")
        raw = bech32.convertbits(data, 5, 8, False)
        return bytes(raw)

    def _mnemonic_to_nip06_key(self):
        root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(self.value))
        return root.derive(NIP06_PATH)

    def _get_pub_xonly(self):
        hex_key = self.value if self.key == HEX else self.get_hex()
        priv = PrivateKey(bytes.fromhex(hex_key))
        return priv.get_public_key().xonly()

    def get_hex(self):
        """Return key in hex format"""
        if self.key == HEX:
            return self.value
        if self.key == NSEC:
            return NostrKey._decode_bech32(self.value).hex()
        # is mnemonic
        nostr_root = self._mnemonic_to_nip06_key()
        return hexlify(nostr_root.secret).decode()

    def get_nsec(self):
        """Return key in nsec format"""
        if self.key == NSEC:
            return self.value
        if self.key == HEX:
            return NostrKey._encode_bech32(bytes.fromhex(self.value), NSEC)
        # is mnemonic
        nostr_root = self._mnemonic_to_nip06_key()
        return NostrKey._encode_bech32(nostr_root.secret, NSEC)

    def get_pub_hex(self):
        """Return pubkey in hex format"""
        if self.key in (HEX, NSEC):
            pub_bytes = self._get_pub_xonly()
            return pub_bytes.hex()
        # is mnemonic
        nostr_root = self._mnemonic_to_nip06_key()
        return hexlify(nostr_root.xonly()).decode()

    def get_npub(self):
        """Return pubkey in npub format"""
        if self.key in (HEX, NSEC):
            pub_bytes = self._get_pub_xonly()
            return NostrKey._encode_bech32(pub_bytes, NPUB)
        # is mnemonic
        nostr_root = self._mnemonic_to_nip06_key()
        return NostrKey._encode_bech32(nostr_root.xonly(), NPUB)


# -------------------


class KMenu(Menu):
    """Customizes the page's menu"""

    def __init__(
        self,
        ctx,
        menu,
        offset=None,
        disable_statusbar=False,
        back_label="Back",
        back_status=lambda: MENU_EXIT,
    ):
        super().__init__(ctx, menu, offset, disable_statusbar, back_label, back_status)
        self.disable_statusbar = False
        if offset is None:
            self.menu_offset = STATUS_BAR_HEIGHT
        else:
            # Always disable status bar if menu has non standard offset
            self.disable_statusbar = True
            self.menu_offset = offset if offset >= 0 else DEFAULT_PADDING

    def new_draw_wallet_indicator(self):
        """Customize the top bar"""
        text = NAME
        if nostrKey.is_loaded():
            if nostrKey.is_mnemonic():
                text = Key.extract_fingerprint(nostrKey.value)
            else:
                text = nostrKey.value[:9] + ELLIPSIS

        if not kboard.is_m5stickv:
            self.ctx.display.draw_hcentered_text(
                text,
                STATUS_BAR_HEIGHT - FONT_HEIGHT - 1,
                theme.highlight_color,
                theme.info_bg_color,
            )
        else:
            self.ctx.display.draw_string(
                24,
                STATUS_BAR_HEIGHT - FONT_HEIGHT - 1,
                text,
                theme.highlight_color,
                theme.info_bg_color,
            )

    def new_draw_network_indicator(self):
        """Don't draw testnet"""

    Menu.draw_wallet_indicator = new_draw_wallet_indicator
    Menu.draw_network_indicator = new_draw_network_indicator


# -------------------


class Klogin(Login):
    """Page to load a Nostr the Key"""

    def __init__(self, ctx):
        super().__init__(ctx)
        shtn_reboot_label = t("Shutdown") if kboard.has_battery else t("Reboot")
        self.menu = KMenu(
            ctx,
            [
                (t("Load Mnemonic"), self.load_key),
                (t("New Mnemonic"), self.new_key),
                (t("Load nsec or hex"), self.load_nsec),
                (t("About"), self.about),
                (shtn_reboot_label, self.shutdown),
            ],
            back_label=None,
        )

    def _load_wallet_key(self, mnemonic):
        nostrKey.load_mnemonic(mnemonic)
        self.ctx.wallet = Wallet(Key(mnemonic, TYPE_SINGLESIG, NETWORKS[MAIN_TXT]))

        return MENU_EXIT

    def load_nsec(self):
        """Load nsec or hex menu item"""

        submenu = Menu(
            self.ctx,
            [
                (t("QR Code"), self._load_nostr_priv_cam),
                (t("Via Manual Input"), self._pre_load_nostr_priv_manual),
                (
                    t("Load from SD card"),
                    None if not self.has_sd_card() else self._load_nostr_priv_sd,
                ),
            ],
        )
        index, status = submenu.run_loop()
        if index == len(submenu.menu) - 1:
            return MENU_CONTINUE
        return status

    def _pre_load_nostr_priv_manual(self):
        submenu = Menu(
            self.ctx,
            [
                (NSEC, lambda ver=NSEC: self._load_nostr_priv_manual(ver)),
                (HEX, lambda ver=HEX: self._load_nostr_priv_manual(ver)),
            ],
        )
        index, status = submenu.run_loop()
        if index == len(submenu.menu) - 1:
            return MENU_CONTINUE
        return status

    def _load_nostr_priv_cam(self):
        from krux.pages.qr_capture import QRCodeCapture

        error_msg = t("Failed to load")
        qr_capture = QRCodeCapture(self.ctx)
        data, _ = qr_capture.qr_capture_loop()
        if data is None:
            self.flash_error(error_msg)
            return MENU_CONTINUE

        try:
            data = data.decode() if not isinstance(data, str) else data
        except:
            self.flash_error(error_msg)
            return MENU_CONTINUE

        return self._load_nostr_priv_key(data)

    def _load_nostr_priv_manual(self, version):
        title = t("Private Key")

        data = ""
        if version == NSEC:
            data = NSEC

        while True:
            if version == NSEC:
                data = self.capture_from_keypad(
                    title, [LETTERS, DIGITS], starting_buffer=data
                )
            else:
                data = self.capture_from_keypad(
                    title, [DIGITS_HEX], starting_buffer=data
                )

            if data == ESC_KEY:
                return MENU_CONTINUE

            if self._load_nostr_priv_key(data) == MENU_EXIT:
                return MENU_EXIT

    def _load_nostr_priv_sd(self):
        from krux.pages.utils import Utils

        # Prompt user for file
        filename, _ = Utils(self.ctx).load_file(prompt=False, only_get_filename=True)

        if not filename:
            return MENU_CONTINUE

        from krux.sd_card import SDHandler

        data = ""
        try:
            with SDHandler() as sd:
                data = sd.read(filename)

            data = data.replace("\r\n", "").replace("\n", "")
        except:
            self.flash_error(t("Failed to load"))
            return MENU_CONTINUE

        return self._load_nostr_priv_key(data)

    def _load_nostr_priv_key(self, data: str):
        data = data.lower()

        self.ctx.display.clear()
        self.ctx.display.draw_hcentered_text(
            t("Private Key") + ":\n\n" + data, max_lines=10, highlight_prefix=":"
        )
        if not self.prompt(
            t("Proceed?"),
            BOTTOM_PROMPT_LINE,
        ):
            return MENU_CONTINUE

        if data.startswith(NSEC):
            nostrKey.load_nsec(data)
        else:
            nostrKey.load_hex(data)

        return MENU_EXIT

    def about(self):
        """Handler for the 'about' menu item"""

        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(
            "Kapp %s\n%s: %s\n\n" % (NAME, t("Version"), VERSION)
            + t("Load or create a key to sign events. Works with NIP-06 and NIP-19.")
        )
        self.ctx.input.wait_for_button()
        return MENU_CONTINUE


# -------------------


class Khome(Home):
    """The page after loading the Key"""

    def __init__(self, ctx):
        super().__init__(ctx)

        shtn_reboot_label = t("Shutdown") if kboard.has_battery else t("Reboot")
        self.menu = KMenu(
            ctx,
            [
                (
                    t("Backup Mnemonic"),
                    (
                        self.backup_mnemonic
                        if not Settings().security.hide_mnemonic
                        and nostrKey.is_mnemonic()
                        else None
                    ),
                ),
                (t("Nostr Keys"), self.nostr_keys),
                (t("Sign Event"), self.sign_message),
                (shtn_reboot_label, self.shutdown),
            ],
            back_label=None,
        )

    def nostr_keys(self):
        """Handler for Nostr Keys menu item"""
        submenu = Menu(
            self.ctx,
            [
                (
                    t("Private Key"),
                    lambda: self.show_key_formats([NSEC, PRIV_HEX]),
                ),
                (t("Public Key"), lambda: self.show_key_formats([NPUB, PUB_HEX])),
            ],
        )
        index, status = submenu.run_loop()
        if index == len(submenu.menu) - 1:
            return MENU_CONTINUE
        return status

    def show_key_formats(self, versions):
        """Create menu to select Nostr keys in text or QR"""

        def _nostr_key_text(version):
            def _save_nostr_to_sd(version):
                from krux.pages.file_operations import SaveFile

                save_page = SaveFile(self.ctx)
                title = version + FILE_SUFFIX
                save_page.save_file(
                    self._get_nostr_key(version),
                    title,
                    title,
                    title + ":",
                    FILE_EXTENSION,
                    save_as_binary=False,
                )

            nostr_text_menu_items = [
                (
                    t("Save to SD card"),
                    (
                        None
                        if not self.has_sd_card()
                        else lambda ver=version: _save_nostr_to_sd(ver)
                    ),
                ),
            ]
            full_nostr_key = (
                self._get_nostr_title(version)
                + ":\n\n"
                + str(self._get_nostr_key(version))
            )
            menu_offset = 5 + len(self.ctx.display.to_lines(full_nostr_key))
            menu_offset *= FONT_HEIGHT
            nostr_key_menu = Menu(self.ctx, nostr_text_menu_items, offset=menu_offset)
            self.ctx.display.clear()
            self.ctx.display.draw_hcentered_text(
                full_nostr_key,
                offset_y=FONT_HEIGHT,
                info_box=True,
                highlight_prefix=":",
            )
            nostr_key_menu.run_loop()

        def _nostr_key_qr(version):
            title = self._get_nostr_title(version)
            nostr_key = str(self._get_nostr_key(version))
            from krux.pages.qr_view import SeedQRView

            seed_qr_view = SeedQRView(self.ctx, data=nostr_key, title=title)
            seed_qr_view.display_qr(allow_export=True, transcript_tools=False)

        pub_key_menu_items = []
        for version in versions:
            title = version if version not in (PRIV_HEX, PUB_HEX) else HEX
            pub_key_menu_items.append(
                (title + " - " + t("Text"), lambda ver=version: _nostr_key_text(ver))
            )
            pub_key_menu_items.append(
                (title + " - " + t("QR Code"), lambda ver=version: _nostr_key_qr(ver))
            )
        pub_key_menu = Menu(self.ctx, pub_key_menu_items)
        while True:
            _, status = pub_key_menu.run_loop()
            if status == MENU_EXIT:
                break

        return MENU_CONTINUE

    def _get_nostr_title(self, version):
        if version == NPUB:
            return "Public Key npub"
        if version == PUB_HEX:
            return "Public Key hex"
        if version == NSEC:
            return "Private Key nsec"
        return "Private Key hex"

    def _get_nostr_key(self, version):
        if version == NPUB:
            return nostrKey.get_npub()
        if version == NSEC:
            return nostrKey.get_nsec()
        if version == PRIV_HEX:
            return nostrKey.get_hex()
        return nostrKey.get_pub_hex()


# -------------------


def run(ctx):
    """Runs this kapp"""

    Klogin(ctx).run()

    if nostrKey.is_loaded():
        Khome(ctx).run()


nostrKey = NostrKey()

# TODO: use try / catch and threat exceptions to avoid error:
# Could not execute nostr
