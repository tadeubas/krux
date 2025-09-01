TEST_QR = bytearray(
    b"\x7fn\xfd\x830\x08v9\xd6\xedj\xa0\xdbUU7\xc8\xa0\xe0_U\x7f\x00i\x00\xe3\xd61P\x08\xf5Q\xef^\xfe`\xe8\xc1\x7f\xdex\x936Y\x91\xb8\xeb\xd29c\xd5\xd4\x7f\x00\n#\xfe\xcd\xd7\rJ\x8e\xd9\xe5\xf8\xb9K\xe6x\x17\xb9\xca\xa0\x9a\x9a\x7f\xbb\x1b\x01"
)

CHINESE_CODEPOINT_MIN = 0x4E00
CHINESE_CODEPOINT_MAX = 0x9FFF
KOREAN_CODEPOINT_MIN = 0xAC00
KOREAN_CODEPOINT_MAX = 0xD7A3


def string_width_px(string):
    import board

    standard_width = board.config["krux"]["display"]["font"][0]
    wide_width = board.config["krux"]["display"]["font_wide"][0]
    print("standard_width:", standard_width)
    print("wide_width:", wide_width)
    string_width = 0

    for c in string:
        if (
            CHINESE_CODEPOINT_MIN <= ord(c) <= CHINESE_CODEPOINT_MAX
            or KOREAN_CODEPOINT_MIN <= ord(c) <= KOREAN_CODEPOINT_MAX
        ):
            string_width += wide_width
        else:
            string_width += standard_width

    return string_width


def test_init(mocker, multiple_devices):
    mocked_settings = mocker.MagicMock()
    mocked_settings.hardware = mocker.MagicMock()
    mocked_settings.hardware.display = mocker.MagicMock()
    mocker.patch("krux.display.lcd", new=mocker.MagicMock())

    import krux
    from krux.display import Display
    import board

    mocker.spy(Display, "initialize_lcd")
    mocker.spy(Display, "set_pmu_backlight")

    if board.config["type"] == "m5stickv":

        # Test the pmu backlight brightness levels
        # for m5stickv, 1 to 5 are valid brightness levels
        # (1 inclusive and 6 exclusive)
        for level in range(1, 6):
            brightness = str(level)
            mocked_settings.hardware.display.brightness = brightness
            mocker.patch("krux.display.Settings", return_value=mocked_settings)

            krux.display.lcd.init.reset_mock()
            Display.set_pmu_backlight.reset_mock()

            d = Display()
            d.initialize_lcd()

            assert isinstance(d, Display)
            d.initialize_lcd.assert_called()
            krux.display.lcd.init.assert_called_once()

            Display.set_pmu_backlight.assert_called_once_with(d, str(level))

            assert "type" in krux.display.lcd.init.call_args.kwargs
            assert (
                krux.display.lcd.init.call_args.kwargs["type"]
                == board.config["lcd"]["lcd_type"]
            )

    elif board.config["type"] == "amigo":
        d = Display()
        d.initialize_lcd()

        assert isinstance(d, Display)
        d.initialize_lcd.assert_called()
        krux.display.lcd.init.assert_called_once()

        assert "invert" in krux.display.lcd.init.call_args.kwargs
        assert krux.display.lcd.init.call_args.kwargs["invert"] == True

    else:
        d = Display()
        d.initialize_lcd()

        assert isinstance(d, Display)
        d.initialize_lcd.assert_called()
        krux.display.lcd.init.assert_called_once()


def test_width(mocker, m5stickv):
    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display

    d = Display()
    d.initialize_lcd()

    d.to_portrait()
    assert d.width() == krux.display.lcd.width()
    krux.display.lcd.width.assert_called()

    d.to_landscape()

    assert d.width() == krux.display.lcd.height()
    krux.display.lcd.height.assert_called()


def test_height(mocker, m5stickv):
    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display

    d = Display()

    d.to_portrait()

    assert d.height() == krux.display.lcd.height()
    krux.display.lcd.height.assert_called()

    d.to_landscape()

    assert d.height() == krux.display.lcd.width()
    krux.display.lcd.width.assert_called()


def test_qr_data_width(mocker, m5stickv):
    from krux.display import Display

    d = Display()
    d.to_portrait()

    mocker.patch.object(d, "width", new=lambda: 135)
    width = d.width()
    mocker.spy(d, "width")
    assert d.qr_data_width() == width // 4

    mocker.patch.object(d, "width", new=lambda: 240)
    width = d.width()
    mocker.spy(d, "width")
    assert d.qr_data_width() == width // 5

    mocker.patch.object(d, "width", new=lambda: 320)
    width = d.width()
    mocker.spy(d, "width")
    assert d.qr_data_width() == width // 6

    d.width.assert_called()


def test_to_landscape(mocker, m5stickv):
    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display, LANDSCAPE

    d = Display()

    d.to_portrait()
    d.to_landscape()

    krux.display.lcd.rotation.assert_called_with(LANDSCAPE)


def test_to_portrait(mocker, m5stickv):
    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display, PORTRAIT

    d = Display()

    d.to_portrait()

    krux.display.lcd.rotation.assert_called_with(PORTRAIT)


def test_to_lines(mocker, m5stickv):
    from krux.display import Display

    cases = [
        # 135 // 8 = 16 chars
        (135, "Two Words", ["Two Words"]),
        (135, "Two  Words", ["Two  Words"]),
        (135, "Two   Words", ["Two   Words"]),
        (135, "Two        Words", ["Two        Words"]),
        (135, "Two\nWords", ["Two", "Words"]),  # case 4
        (135, "Two\n\nWords", ["Two", "", "Words"]),
        (135, "Two\n\n\nWords", ["Two", "", "", "Words"]),
        (135, "Two\n\n\n\nWords", ["Two", "", "", "", "Words"]),
        (135, "Two\n\n\n\n\nWords", ["Two", "", "", "", "", "Words"]),
        (135, "\nTwo\nWords\n", ["", "Two", "Words"]),  # case 9
        (135, "\n\nTwo\nWords\n\n", ["", "", "Two", "Words", ""]),  # case 10
        (135, "\n\n\nTwo\nWords\n\n\n", ["", "", "", "Two", "Words", "", ""]),
        (135, "More Than Two Words", ["More Than Two", "Words"]),  # 13 + 5 chars
        (
            135,
            "A bunch of words that span multiple lines..",
            ["A bunch of words", "that span", "multiple lines.."],  # 16 + 9 + 16 chars
        ),
        (
            135,
            "tpubDCDuqu5HtBX2aD7wxvnHcj1DgFN1UVgzLkA1Ms4Va4P7TpJ3jDknkPLwWT2SqrKXNNAtJBCPcbJ8Tcpm6nLxgFapCZyhKgqwcEGv1BVpD7s",
            [
                "tpubDCDuqu5HtBX2",
                "aD7wxvnHcj1DgFN1",
                "UVgzLkA1Ms4Va4P7",
                "TpJ3jDknkPLwWT2S",
                "qrKXNNAtJBCPcbJ8",
                "Tcpm6nLxgFapCZyh",
                "KgqwcEGv1BVpD7s",
            ],
        ),
        (
            135,
            "xpub: tpubDCDuqu5HtBX2aD7wxvnHcj1DgFN1UVgzLkA1Ms4Va4P7TpJ3jDknkPLwWT2SqrKXNNAtJBCPcbJ8Tcpm6nLxgFapCZyhKgqwcEGv1BVpD7s",
            [
                "xpub:",
                "tpubDCDuqu5HtBX2",
                "aD7wxvnHcj1DgFN1",
                "UVgzLkA1Ms4Va4P7",
                "TpJ3jDknkPLwWT2S",
                "qrKXNNAtJBCPcbJ8",
                "Tcpm6nLxgFapCZyh",
                "KgqwcEGv1BVpD7s",
            ],
        ),  # case 15
        (135, "Log Level\nNONE", ["Log Level", "NONE"]),
        (
            135,
            "New firmware detected.\n\nSHA256:\n1621f9c0e9ccb7995a29327066566adfd134e19109d7ce8e52aad7bd7dcce121\n\n\n\nInstall?",
            [
                "New firmware",
                "detected.",
                "",
                "SHA256:",
                "1621f9c0e9ccb799",
                "5a29327066566adf",
                "d134e19109d7ce8e",
                "52aad7bd7dcce121",
                "",
                "",
                "",
                "Install?",
            ],
        ),
        # (240 - 2 * 10) // 8 = 27 chars
        (240, "Two Words", ["Two Words"]),
        (240, "Two\nWords", ["Two", "Words"]),
        (240, "Two\n\nWords", ["Two", "", "Words"]),  # case 20
        (240, "Two\n\n\nWords", ["Two", "", "", "Words"]),
        (240, "Two\n\n\n\nWords", ["Two", "", "", "", "Words"]),
        (240, "Two\n\n\n\n\nWords", ["Two", "", "", "", "", "Words"]),
        (240, "\nTwo\nWords\n", ["", "Two", "Words"]),
        (240, "\n\nTwo\nWords\n\n", ["", "", "Two", "Words", ""]),  # case 25
        (240, "\n\n\nTwo\nWords\n\n\n", ["", "", "", "Two", "Words", "", ""]),
        (240, "More Than Two Words", ["More Than Two Words"]),
        (
            240,
            "A bunch of text that spans multiple lines..",
            ["A bunch of text that spans", "multiple lines.."],  # 26 + 16 chars
        ),
        (
            240,
            "tpubDCDuqu5HtBX2aD7wxvnHcj1DgFN1UVgzLkA1Ms4Va4P7TpJ3jDknkPLwWT2SqrKXNNAtJBCPcbJ8Tcpm6nLxgFapCZyhKgqwcEGv1BVpD7s",
            [
                "tpubDCDuqu5HtBX2aD7wxvnHcj1",
                "DgFN1UVgzLkA1Ms4Va4P7TpJ3jD",
                "knkPLwWT2SqrKXNNAtJBCPcbJ8T",
                "cpm6nLxgFapCZyhKgqwcEGv1BVp",
                "D7s",
            ],
        ),
        (
            240,
            "xpub: tpubDCDuqu5HtBX2aD7wxvnHcj1DgFN1UVgzLkA1Ms4Va4P7TpJ3jDknkPLwWT2SqrKXNNAtJBCPcbJ8Tcpm6nLxgFapCZyhKgqwcEGv1BVpD7s",
            [
                "xpub:",
                "tpubDCDuqu5HtBX2aD7wxvnHcj1",
                "DgFN1UVgzLkA1Ms4Va4P7TpJ3jD",
                "knkPLwWT2SqrKXNNAtJBCPcbJ8T",
                "cpm6nLxgFapCZyhKgqwcEGv1BVp",
                "D7s",
            ],
        ),  # case 30
        (240, "Log Level\nNONE", ["Log Level", "NONE"]),
        (
            240,
            "New firmware detected.\n\nSHA256:\n1621f9c0e9ccb7995a29327066566adfd134e19109d7ce8e52aad7bd7dcce121\n\n\n\nInstall?",
            [
                "New firmware detected.",
                "",
                "SHA256:",
                "1621f9c0e9ccb7995a293270665",
                "66adfd134e19109d7ce8e52aad7",
                "bd7dcce121",
                "",
                "",
                "",
                "Install?",
            ],
        ),
    ]
    for i, case in enumerate(cases):
        print("case:", i)
        mocker.patch(
            "krux.display.lcd",
            new=mocker.MagicMock(width=mocker.MagicMock(return_value=case[0])),
        )

        from krux.kboard import kboard

        kboard.is_m5stickv = case[0] == 135

        d = Display()
        d.to_portrait()

        lines = d.to_lines(case[1])

        assert lines == case[2]

    print("Extra test outside above cases...")

    # Test a text that don't fit in the screen
    LCD_WIDTH = 240
    MAX_LINES = 3
    mocker.patch(
        "krux.display.lcd",
        new=mocker.MagicMock(width=mocker.MagicMock(return_value=LCD_WIDTH)),
    )
    long_text = "A really long text. " * 6
    d = Display()
    d.to_portrait()
    lines = d.to_lines(long_text, max_lines=MAX_LINES)
    cut_text = [
        "A really long text. A",
        "really long text. A really",
        "long text. A really long…",
    ]
    assert lines == cut_text


def test_to_lines_exact_match_amigo(mocker, amigo):
    from krux.display import Display

    cases = [
        # (320 - 2 * 10) // 12 = 24 chars
        (320, "01234 0123456789012345678", ["01234 0123456789012345678"]),
        (
            320,
            "0123456789 01234567890 01234",
            ["0123456789 01234567890", "01234"],
        ),  # 22 + 5 chars
        (320, "01234567890123456789012345", ["0123456789012345678901234", "5"]),
        (
            320,
            "01234 0123456789012345678\n01234 0123456789012345678",
            ["01234 0123456789012345678", "01234 0123456789012345678"],
        ),
        (
            320,
            "01 34 0123456789012345678\n01234 0123456789012345678",
            ["01 34 0123456789012345678", "01234 0123456789012345678"],
        ),
        (
            320,
            "01 01 01 01 01 01 01 01 0\n01 01 01 01 01 01 01 0123",
            ["01 01 01 01 01 01 01 01 0", "01 01 01 01 01 01 01 0123"],
        ),
        (
            320,
            "0 0 0 0 0 0 0 0 0 0 0 0 0\n01 01 01 01 01 01 01 0123",
            ["0 0 0 0 0 0 0 0 0 0 0 0 0", "01 01 01 01 01 01 01 0123"],
        ),
        (
            320,
            "01 345 0123456789012345678\n01234 0123456789012345678",
            ["01 345", "0123456789012345678", "01234 0123456789012345678"],
        ),
    ]
    for i, case in enumerate(cases):
        print("case:", i)
        mocker.patch(
            "krux.display.lcd",
            new=mocker.MagicMock(width=mocker.MagicMock(return_value=case[0])),
        )
        d = Display()
        d.to_portrait()
        lines = d.to_lines(case[1])
        print(lines)
        assert lines == case[2]


def test_to_lines_korean(mocker, m5stickv):
    from krux.display import Display, lcd

    mock_settings = mocker.MagicMock()
    mock_settings.i18n.locale = "ko-KR"

    mocker.spy(lcd, "string_has_wide_glyph")
    mocker.patch("krux.display.Settings", return_value=mock_settings)
    mocker.patch("krux.display.lcd.width", return_value=135)

    text = "안녕"
    d = Display()
    d.to_portrait()
    result = d.to_lines(text)

    lcd.string_has_wide_glyph.assert_called_once_with("안녕")
    assert result == ["안녕"]


def test_to_lines_japanese(mocker, m5stickv):
    from krux.display import Display, lcd

    mock_settings = mocker.MagicMock()
    mock_settings.i18n.locale = "ja-JP"

    mocker.spy(lcd, "string_has_wide_glyph")
    mocker.patch("krux.display.Settings", return_value=mock_settings)
    mocker.patch("krux.display.lcd.width", return_value=135)

    text = "こんにちは"
    d = Display()
    d.to_portrait()
    result = d.to_lines(text)

    lcd.string_has_wide_glyph.assert_called_once_with("こんにちは")
    assert result == ["こんにちは"]


def test_to_lines_chinese(mocker, m5stickv):
    from krux.display import Display, lcd

    mock_settings = mocker.MagicMock()
    mock_settings.i18n.locale = "zh-CN"

    mocker.spy(lcd, "string_has_wide_glyph")
    mocker.patch("krux.display.Settings", return_value=mock_settings)
    mocker.patch("krux.display.lcd.width", return_value=135)

    text = "你好"
    d = Display()
    d.to_portrait()
    result = d.to_lines(text)

    lcd.string_has_wide_glyph.assert_called_once_with("你好")
    assert result == ["你好"]


def test_to_lines_endpos(mocker, m5stickv):
    from krux.display import Display, FONT_WIDTH, TOTAL_LINES

    # m5stick has max 16 chars per line and 16 lines
    max_lines = 16

    mocker.patch("krux.display.lcd.width", return_value=135)
    text = "I am a long line of text, and I will be repeated." * 30
    d = Display()
    d.to_portrait()
    lines, endpos = d._to_lines_endpos(text, max_lines)
    assert len(lines) == max_lines
    assert endpos == 249

    # test exactly enough to finish the page w/o ellipsis
    for white in (" ", "\n"):
        print("whitespace:", repr(white))
        text = white.join(
            ["line {:02d} 16 chars".format(x) for x in range(1, max_lines + 1)]
        )
        d = Display()
        d.to_portrait()
        lines, endpos = d._to_lines_endpos(text, max_lines)
        assert len(lines) == max_lines
        assert endpos == len(text)
        assert lines[-1][-1] != "\u2026"  # no ellipsis

        # ... and that one char too big would span a page w/ ellipsis
        text += "+"
        lines, endpos = d._to_lines_endpos(text, max_lines)
        assert len(lines) == max_lines
        assert endpos == len(text) - len("chars+")
        assert lines[-1][-1] == "\u2026"  # has ellipsis
        lines, endpos = d._to_lines_endpos(text[endpos:], max_lines)
        assert len(lines) == 1
        assert lines[-1] == "chars+"  # space gets stripped

    # without anywhere convenient to break, force break
    text = "".join(["line_{:02d}_16_chars".format(x) for x in range(1, max_lines + 1)])
    d = Display()
    d.to_portrait()
    lines, endpos = d._to_lines_endpos(text, max_lines)
    assert len(lines) == max_lines
    assert endpos == len(text)
    assert lines[-1][-1] != "\u2026"  # no ellipsis

    # ... and that one char too big would span a page w/ ellipsis
    text += "+"
    lines, endpos = d._to_lines_endpos(text, max_lines)
    old_end_pos = endpos
    assert len(lines) == max_lines
    assert endpos == len(text) - len("s+")
    assert lines[-1][-1] == "\u2026"  # has ellipsis
    lines, endpos = d._to_lines_endpos(text[endpos:], max_lines)
    assert len(lines) == 1
    assert lines[-1] == "s+"

    # simple cases

    chars_per_line = 10
    display_width = FONT_WIDTH * chars_per_line
    mocker.patch("krux.display.lcd.width", return_value=display_width)

    d = Display()
    d.to_portrait()

    text = "0123456789abc"
    max_lines = 1
    lines, endpos = d._to_lines_endpos(text, max_lines)
    print(lines, endpos, text[endpos:])
    assert len(lines) == max_lines
    assert len(lines[0]) == chars_per_line
    assert "012345678…" == lines[0]
    assert "9" not in lines[0]
    assert text[endpos:] == "9abc"

    text = "0123456789abc" * 13  # 13 * 13 = 169
    text += "x"  # 169 + 1 = 170
    max_lines = TOTAL_LINES  # 17
    print(TOTAL_LINES)
    lines, endpos = d._to_lines_endpos(text, max_lines)
    print(lines, len(lines), endpos)
    for i in range(max_lines):
        assert len(lines[i]) == chars_per_line

    lines, _ = d._to_lines_endpos(text[endpos:])
    assert lines == [""]  # vazio


def test_outline(mocker, m5stickv):
    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display

    d = Display()

    d.outline(0, 0, 100, 100, krux.display.lcd.WHITE)

    krux.display.lcd.draw_outline.assert_called_with(
        0, 0, 100, 100, krux.display.lcd.WHITE
    )


def test_outline_flipped(mocker, amigo):
    mock_lcd = mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display

    d = Display()
    mocker.patch.object(d, "width", new=lambda: 480)
    d.outline(0, 0, 100, 100, krux.display.lcd.WHITE)

    mock_lcd.draw_outline.assert_called_with(379, 0, 100, 100, krux.display.lcd.WHITE)


def test_draw_line(mocker, m5stickv):
    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display

    d = Display()

    d.draw_line(100, 0, 100, 100, krux.display.lcd.WHITE)

    krux.display.lcd.draw_line.assert_called_with(
        100, 0, 100, 100, krux.display.lcd.WHITE
    )


def test_draw_line_on_inverted_display(mocker, amigo):
    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display

    d = Display()
    mocker.patch.object(d, "width", new=lambda: 480)

    d.draw_line(100, 0, 100, 100, krux.display.lcd.WHITE)

    krux.display.lcd.draw_line.assert_called_with(
        480 - 100 - 1, 0, 480 - 100 - 1, 100, krux.display.lcd.WHITE
    )


def test_hline(mocker, m5stickv):
    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display

    d = Display()
    mocker.patch.object(d, "width", new=lambda: 480)

    d.draw_hline(0, 0, 100, krux.display.lcd.WHITE)
    krux.display.lcd.draw_line.assert_called_with(0, 0, 100, 0, krux.display.lcd.WHITE)


def test_vline(mocker, m5stickv):
    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display

    d = Display()
    mocker.patch.object(d, "width", new=lambda: 480)

    d.draw_vline(0, 0, 100, krux.display.lcd.WHITE)
    krux.display.lcd.draw_line.assert_called_with(0, 0, 0, 100, krux.display.lcd.WHITE)


def test_fill_rectangle(mocker, m5stickv):
    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display

    d = Display()

    d.fill_rectangle(0, 0, 100, 100, krux.display.lcd.WHITE)

    krux.display.lcd.fill_rectangle.assert_called_with(
        0, 0, 100, 100, krux.display.lcd.WHITE, 0
    )


def test_fill_rectangle_on_inverted_display(mocker, amigo):
    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display

    d = Display()
    mocker.patch.object(d, "width", new=lambda: 480)

    d.fill_rectangle(0, 0, 100, 100, krux.display.lcd.WHITE)

    krux.display.lcd.fill_rectangle.assert_called_with(
        480 - 0 - 100, 0, 100, 100, krux.display.lcd.WHITE, 0
    )


def test_draw_string(mocker, m5stickv):
    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display

    d = Display()

    d.draw_string(0, 0, "Hello world", krux.display.lcd.WHITE, krux.display.lcd.BLACK)

    krux.display.lcd.draw_string.assert_called_with(
        0, 0, "Hello world", krux.display.lcd.WHITE, krux.display.lcd.BLACK
    )


def test_draw_string_on_inverted_display(mocker, amigo):
    import krux
    from krux.display import Display

    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    mocker.patch("krux.display.lcd.string_width_px", side_effect=string_width_px)

    d = Display()
    mocker.patch.object(d, "width", new=lambda: 480)

    d.draw_string(0, 0, "Hello world", krux.display.lcd.WHITE, krux.display.lcd.BLACK)

    krux.display.lcd.draw_string.assert_called_with(
        480 - 0 - 132, 0, "Hello world", krux.display.lcd.WHITE, krux.display.lcd.BLACK
    )


def test_draw_hcentered_text(mocker, m5stickv):
    import krux
    from krux.display import Display, DEFAULT_PADDING
    from krux.themes import theme

    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    mocker.patch("krux.display.lcd.string_width_px", side_effect=string_width_px)

    d = Display()
    mocker.patch.object(d, "width", new=lambda: 135)
    mocker.spy(d, "draw_string")

    d.draw_hcentered_text(
        "Hello world", 50, krux.display.lcd.WHITE, krux.display.lcd.BLACK
    )

    d.draw_string.assert_called_with(
        23, 50, "Hello world", krux.display.lcd.WHITE, krux.display.lcd.BLACK
    )

    d = Display()
    mocker.patch.object(d, "width", new=lambda: 135)
    mocker.spy(d, "draw_string")

    d.draw_hcentered_text("prefix: highlighted", highlight_prefix=":")

    d.draw_string.assert_has_calls(
        [
            mocker.call(
                39,
                DEFAULT_PADDING,
                "prefix:",
                theme.highlight_color,
                theme.bg_color,
            ),
            mocker.call(23, 24, "highlighted", theme.fg_color, theme.bg_color),
        ]
    )

    d = Display()
    mocker.patch.object(d, "width", new=lambda: 135)
    mocker.spy(d, "draw_string")

    d.draw_hcentered_text(
        "This is a very big prefix that don't fit one line: highlighted2",
        highlight_prefix=":",
    )

    d.draw_string.assert_has_calls(
        [
            mocker.call(
                47,
                52,
                "line:",
                theme.highlight_color,
                theme.bg_color,
            ),
            mocker.call(
                15,
                38,
                "don't fit one",
                theme.highlight_color,
                theme.bg_color,
            ),
            mocker.call(
                7,
                24,
                "big prefix that",
                theme.highlight_color,
                theme.bg_color,
            ),
            mocker.call(
                11,
                DEFAULT_PADDING,
                "This is a very",
                theme.highlight_color,
                theme.bg_color,
            ),
            mocker.call(19, 66, "highlighted2", theme.fg_color, theme.bg_color),
        ]
    )

    d = Display()
    mocker.patch.object(d, "width", new=lambda: 135)
    mocker.spy(d, "draw_string")

    d.draw_hcentered_text(
        "This is\n\n a very\nbig prefix that don't fit one line: highlighted2",
        highlight_prefix=":",
    )

    d.draw_string.assert_has_calls(
        [
            mocker.call(
                47,
                80,
                "line:",
                theme.highlight_color,
                theme.bg_color,
            ),
            mocker.call(
                15,
                66,
                "don't fit one",
                theme.highlight_color,
                theme.bg_color,
            ),
            mocker.call(
                7,
                52,
                "big prefix that",
                theme.highlight_color,
                theme.bg_color,
            ),
            mocker.call(19, 94, "highlighted2", theme.fg_color, theme.bg_color),
        ]
    )


def test_draw_hcentered_text_on_inverted_display(mocker, amigo):
    import krux
    from krux.display import Display

    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    mocker.patch("krux.display.lcd.string_width_px", side_effect=string_width_px)

    d = Display()
    mocker.patch.object(d, "width", new=lambda: 480)
    mocker.spy(d, "draw_string")

    d.draw_hcentered_text(
        "Hello world", 50, krux.display.lcd.WHITE, krux.display.lcd.BLACK
    )

    d.draw_string.assert_called_with(
        174, 50, "Hello world", krux.display.lcd.WHITE, krux.display.lcd.BLACK
    )


def test_draw_infobox(mocker, amigo):
    from krux.display import Display, DEFAULT_PADDING, FONT_HEIGHT, FONT_WIDTH
    from krux.themes import WHITE, BLACK, DARKGREY

    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    mocker.patch("krux.display.lcd.string_width_px", side_effect=string_width_px)

    d = Display()
    mocker.patch.object(d, "width", new=lambda: 320)
    mocker.spy(d, "fill_rectangle")
    mocker.spy(d, "draw_string")

    d.draw_hcentered_text("Hello world", DEFAULT_PADDING, WHITE, BLACK, info_box=True)

    d.fill_rectangle.assert_called_with(
        DEFAULT_PADDING - 3,
        DEFAULT_PADDING - 1,
        d.width() - 2 * DEFAULT_PADDING + 6,
        FONT_HEIGHT + 2,
        DARKGREY,
        FONT_WIDTH,
    )
    d.draw_string.assert_called_with(
        (d.width() - len("Hello world") * FONT_WIDTH) // 2,
        DEFAULT_PADDING,
        "Hello world",
        WHITE,
        DARKGREY,
    )


def test_draw_centered_text(mocker, m5stickv):
    import krux
    from krux.display import Display

    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    mocker.patch("krux.display.lcd.string_width_px", side_effect=string_width_px)

    d = Display()
    mocker.patch.object(d, "width", new=lambda: 135)
    mocker.patch.object(d, "height", new=lambda: 240)
    mocker.spy(d, "draw_hcentered_text")

    d.draw_centered_text("Hello world", krux.display.lcd.WHITE, 0)

    d.draw_hcentered_text.assert_called_with(
        ["Hello world"], 113, krux.display.lcd.WHITE, 0, highlight_prefix=""
    )


def test_draw_qr_code(mocker, m5stickv):
    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display, QR_DARK_COLOR, QR_LIGHT_COLOR

    d = Display()
    mocker.patch.object(d, "width", new=lambda: 135)

    d.draw_qr_code(TEST_QR)

    krux.display.lcd.draw_qr_code_binary.assert_called_with(
        0, 0, TEST_QR, 135, QR_DARK_COLOR, QR_LIGHT_COLOR, QR_LIGHT_COLOR
    )


def test_flash_text(mocker, m5stickv):
    from krux.display import Display, FLASH_MSG_TIME
    from krux.themes import WHITE
    import time

    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    mocker.patch("krux.display.lcd.string_width_px", side_effect=string_width_px)

    d = Display()
    mocker.patch.object(d, "width", new=lambda: 135)
    mocker.patch.object(d, "height", new=lambda: 240)
    mocker.spy(d, "clear")
    mocker.spy(d, "draw_centered_text")

    d.flash_text("test", WHITE)

    d.clear.assert_called()
    d.draw_centered_text.assert_called_with("test", WHITE, highlight_prefix="")
    time.sleep_ms.assert_called_with(FLASH_MSG_TIME)


def test_max_menu_lines(mocker, m5stickv):
    from krux.display import Display

    mocker.patch("krux.display.lcd", new=mocker.MagicMock())

    d = Display()
    mocker.patch.object(d, "width", new=lambda: 135)
    mocker.patch.object(d, "height", new=lambda: 240)

    cases = (
        [(i, 8) for i in range(0, 16)]
        + [(i, 7) for i in range(17, 45)]
        + [(i, 6) for i in range(45, 73)]
        + [(i, 5) for i in range(73, 101)]
        + [(i, 4) for i in range(101, 129)]
        + [(i, 3) for i in range(129, 157)]
        + [(i, 2) for i in range(157, 185)]
    )
    menu_lines = [
        (
            "Very big text menu item that spans multiple lines and occupy space of other menu item",
            None,
        ),
        ("menu item", None),
        ("menu item", None),
        ("menu item", None),
    ]
    for line_offset, expected_lines in cases:
        lines = d.max_menu_lines(line_offset=line_offset)
        assert lines == expected_lines
        lines = d.max_menu_lines(line_offset, menu_lines)
        assert (
            lines == expected_lines - 1
        )  # reduce the number because the menu param has an entry with multiple lines
        lines = d.max_menu_lines(line_offset, menu_lines[1:])
        assert lines == expected_lines  # removed the entry that spans multiple lines


def test_render_image(mocker, multiple_devices):
    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display
    import board

    d = Display()
    img = mocker.MagicMock()

    # Test non-compact rendering
    d.render_image(img, title_lines=0)
    if board.config["type"] == "m5stickv":
        # img object is modified in place(zoom out) for m5stickv
        assert krux.display.lcd.display.call_args.kwargs["oft"] == (0, 0)
        assert krux.display.lcd.display.call_args.kwargs["roi"] == (68, 52, 185, 135)
    elif board.config["type"] == "amigo":
        krux.display.lcd.display.assert_called_once_with(
            img, oft=(40, 40), roi=(0, 0, 320, 240)
        )
    elif board.config["type"] == "dock":
        krux.display.lcd.display.assert_called_once_with(
            img, oft=(0, 0), roi=(8, 0, 304, 240)
        )
    elif board.config["type"] == "cube":
        krux.display.lcd.display.assert_called_once_with(
            img, oft=(0, 0), roi=(48, 0, 224, 240)
        )


def test_render_image_with_title(mocker, multiple_devices):
    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display
    import board

    d = Display()
    img = mocker.MagicMock()

    # Test compact rendering
    d.render_image(img, title_lines=1)
    if board.config["type"] == "m5stickv":
        # img object is modified in place(zoom out) for m5stickv
        assert krux.display.lcd.display.call_args.kwargs["oft"] == (24, 0)
        assert krux.display.lcd.display.call_args.kwargs["roi"] == (92, 52, 161, 135)
    elif board.config["type"] == "amigo":
        krux.display.lcd.display.assert_called_once_with(
            img, oft=(40, 40), roi=(0, 0, 320, 240)
        )
    elif board.config["type"] == "dock":
        krux.display.lcd.display.assert_called_once_with(
            img, oft=(26, 0), roi=(34, 0, 278, 240)
        )
    elif board.config["type"] == "cube":
        krux.display.lcd.display.assert_called_once_with(
            img, oft=(24, 0), roi=(72, 0, 200, 240)
        )


def test_render_image_with_double_subtitle(mocker, multiple_devices):
    # Case for filling the flash with camera entropy, where there'll be:
    # Title at the top
    # Entropy measurement and progress bar at the bottom

    mocker.patch("krux.display.lcd", new=mocker.MagicMock())
    import krux
    from krux.display import Display
    import board

    d = Display()
    img = mocker.MagicMock()

    # Test compact rendering
    d.render_image(img, title_lines=1, double_subtitle=True)
    if board.config["type"] == "m5stickv":
        # img object is modified in place(zoom out) for m5stickv
        assert krux.display.lcd.display.call_args.kwargs["oft"] == (24, 0)
        assert krux.display.lcd.display.call_args.kwargs["roi"] == (92, 52, 161, 135)
    elif board.config["type"] == "amigo":
        krux.display.lcd.display.assert_called_once_with(
            img, oft=(40, 40), roi=(0, 0, 320, 240)
        )
    elif board.config["type"] == "dock":
        krux.display.lcd.display.assert_called_once_with(
            img, oft=(26, 0), roi=(34, 0, 262, 240)
        )
    elif board.config["type"] == "cube":
        krux.display.lcd.display.assert_called_once_with(
            img, oft=(24, 0), roi=(72, 0, 186, 240)
        )


def test_offset(mocker, multiple_devices):
    from krux.display import Display, BOTTOM_LINE, MINIMAL_PADDING
    from krux.kboard import kboard

    d = Display()
    if kboard.is_cube:
        assert d.qr_offset() == BOTTOM_LINE
    else:
        assert d.qr_offset() == d.width() + MINIMAL_PADDING
    assert d.qr_offset(10) == 10 + MINIMAL_PADDING
