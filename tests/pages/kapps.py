import pytest
from unittest.mock import patch
from . import create_ctx


def test_parse_all_flash_apps(m5stickv, mocker):
    from krux.pages.kapps import Kapps
    from krux.sd_card import MPY_FILE_EXTENSION
    from krux.input import BUTTON_PAGE, BUTTON_ENTER
    import os
    from krux.settings import FLASH_PATH

    #################################
    print("Case 1: no file with MPY_FILE_EXTENSION")

    mocker.patch(
        "os.listdir",
        new=mocker.MagicMock(return_value=["somefile", "otherfile"]),
    )

    ctx = create_ctx(mocker, None)
    kapps = Kapps(ctx)

    signed_apps = kapps.parse_all_flash_apps()
    assert len(signed_apps) == 0


    ################################
    print("Case 2: unsigned file, prompt for deletion, user deny, ValueError")

    # one unsigned file
    unsigned_file = "somefile" + MPY_FILE_EXTENSION
    mocker.patch(
        "os.listdir",
        new=mocker.MagicMock(return_value=[unsigned_file]),
    )

    # User deny prompt
    ctx.input.wait_for_button = mocker.MagicMock(side_effect=[BUTTON_PAGE])

    # unsigned file
    with pytest.raises(ValueError, match="Unsigned apps found in flash"):
        signed_apps = kapps.parse_all_flash_apps()
        assert len(signed_apps) == 0


    ################################
    print("Case 3: unsigned file, prompt for deletion, user allow, remove unsigned file")

    # User accept prompt
    ctx.input.wait_for_button = mocker.MagicMock(side_effect=[BUTTON_ENTER])

    # Mock file remove
    mocker.patch("os.remove", new=mocker.MagicMock())

    signed_apps = kapps.parse_all_flash_apps()
    assert len(signed_apps) == 0

    flash_path_prefix = "/%s/" % FLASH_PATH
    os.remove.assert_called_with(flash_path_prefix + unsigned_file)


    ################################
    print("Case 4: signed file")

    # one unsigned file
    signed_file = "sigfile" + MPY_FILE_EXTENSION
    mocker.patch(
        "os.listdir",
        new=mocker.MagicMock(return_value=[signed_file]),
    )
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"signature data"))
    mocker.patch.object(kapps, "valid_signature", new=lambda data, hash: True)

    signed_apps = kapps.parse_all_flash_apps()
    assert len(signed_apps) == 1
    assert signed_file in signed_apps


def test_valid_signature(m5stickv, mocker):
    from krux.pages.kapps import Kapps

    mocker.patch(
        "os.listdir",
        new=mocker.MagicMock(return_value=[]),
    )

    ctx = create_ctx(mocker, None)
    kapps = Kapps(ctx)

    ########################################
    print("Case 1: invalid pubkey()")

    mocker.patch("krux.firmware.get_pubkey", new=lambda: None)

    with pytest.raises(ValueError, match="Invalid public key"):
        kapps.valid_signature(None, None)


    ########################################
    print("Case 2: valid signature")

    mocker.patch("krux.firmware.get_pubkey", new=lambda: "Valid pubkey")
    mocker.patch("krux.firmware.check_signature", new=lambda pubk, sig, hash: True)

    sig = kapps.valid_signature(None, None)
    assert sig



