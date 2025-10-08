import pytest
from . import create_ctx



def test_nostrkey(mocker, m5stickv):
    from kapps.nostr import NostrKey, MNEMONIC, HEX, NSEC, NPUB, PUB_HEX

    # Test vectors from NIP-06: https://github.com/nostr-protocol/nips/blob/master/06.md
    tests = [
        {
            MNEMONIC:"leader monkey parrot ring guide accident before fence cannon height naive bean",
            HEX:"7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a",
            NSEC:"nsec10allq0gjx7fddtzef0ax00mdps9t2kmtrldkyjfs8l5xruwvh2dq0lhhkp",
            PUB_HEX:"17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",
            NPUB:"npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu"
        },
        {
            MNEMONIC:"what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade",
            HEX:"c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add",
            NSEC:"nsec1c9wh8xy5eqdzln7n5t0ctgxjcrdug73gp5yj0x03gntn67h83twssdfhel",
            PUB_HEX:"d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573",
            NPUB:"npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h",
        }
    ]

    for n, t in enumerate(tests):
        print(n, t)
        for version in (MNEMONIC, HEX, NSEC):
            nkey = NostrKey()
            assert not nkey.is_loaded()
            if version == MNEMONIC:
                nkey.load_mnemonic(t[MNEMONIC])
            elif version == HEX:
                nkey.load_hex(t[HEX])
            elif version == NSEC:
                nkey.load_nsec(t[NSEC])

            assert nkey.is_loaded()

            if version in (HEX, NSEC):
                with pytest.raises(ValueError):
                    nkey.get_mnemonic()
            else:
                assert nkey.get_mnemonic() == t[MNEMONIC]
            
            assert nkey.get_hex() == t[HEX]
            assert nkey.get_nsec() == t[NSEC]
            assert nkey.get_pub_hex() == t[PUB_HEX]
            assert nkey.get_npub() == t[NPUB]

        with pytest.raises(ValueError):
            nkey.load_hex(t[HEX][:-1])

        with pytest.raises(ValueError):
            nkey.load_nsec(t[NSEC][:-1])

        with pytest.raises(ValueError):
            nkey.load_nsec(t[NSEC].replace(NSEC, NPUB))

