# The MIT License (MIT)

# Copyright (c) 2021-2023 Krux contributors

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
import os
import pygame as pg

M5STICKV = "maixpy_m5stickv"
AMIGO = "maixpy_amigo"
PC = "maixpy_pc"
DOCK = "maixpy_dock"
YAHBOOM = "maixpy_yahboom"
CUBE = "maixpy_cube"
WONDER_MV = "maixpy_wonder_mv"
WONDER_K = "maixpy_wonder_k"

WINDOW_SIZES = {
    M5STICKV: (320, 640),
    AMIGO: (480, 768),
    PC: (480, 640),
    DOCK: (440, 820),
    YAHBOOM: (450, 600),
    CUBE: (484, 612),
    WONDER_MV: (410, 590),
    WONDER_K: (500, 650),
}


def with_prefix(device):
    return device if device.startswith("maixpy_") else "maixpy_" + device


images = {}


def load_image(device):
    device = with_prefix(device)
    # TODO: remove WONDER_K after img is ready
    if device == PC or device == WONDER_K:
        return None
    if device not in images:
        images[device] = pg.image.load(
            os.path.join("assets", "%s.png" % device)
        ).convert_alpha()
    return images[device]


fonts = {}


def load_font(device):
    device = with_prefix(device)
    if device not in fonts:
        if device in (M5STICKV, CUBE):
            fonts[device] = [
                pg.freetype.Font(
                   os.path.join("..", "firmware", "font", "ter-u14n.bdf"),
                ),
                pg.freetype.Font(
                   os.path.join("..", "firmware", "font", "FusionPixel-14.bdf"),
                ),
            ]
        elif device in (DOCK, YAHBOOM, WONDER_MV, WONDER_K):
            fonts[device] = [
                pg.freetype.Font(
                    os.path.join("..", "firmware", "font", "ter-u16n.bdf")
                ),
                pg.freetype.Font(
                    os.path.join("..", "firmware", "font", "unifont-16.bdf")
                ),
        ]
        else:
            fonts[device] = [
                pg.freetype.Font(
                    os.path.join("..", "firmware", "font", "ter-u24b.bdf")
                ),
                pg.freetype.Font(
                    os.path.join("..", "firmware", "font", "NotoSansCJK-24.bdf")
                ),
            ]

    return fonts[device]


def screenshot_rect(device):
    screen = pg.display.get_surface()
    if device == PC:
        return screen.get_rect()

    rect = load_image(device).get_rect()
    if device == M5STICKV:
        rect.width -= 20
        rect.height -= 205
        rect.center = (
            screen.get_rect().center[0] - 1,
            screen.get_rect().center[1] + 57,
        )
    elif device == AMIGO:
        rect.width -= 370
        rect.height -= 95
        rect.center = (
            screen.get_rect().center[0],
            screen.get_rect().center[1],
        )
    elif device == DOCK:
        rect.width -= 73
        rect.height -= 169
        rect.center = (
            screen.get_rect().center[0] + 1,
            screen.get_rect().center[1] + 74,
        )
    elif device == YAHBOOM:
        rect.width -= 134
        rect.height -= 155
        rect.center = (
            screen.get_rect().center[0],
            screen.get_rect().center[1] + 29,
        )
    elif device == CUBE:
        rect.width -= 58
        rect.height -= 160
        rect.center = (
            screen.get_rect().center[0] + 1,
            screen.get_rect().center[1] - 13,
        )
    elif device == WONDER_MV:
        rect.width -= 88
        rect.height -= 129
        rect.center = (
            screen.get_rect().center[0] - 0,
            screen.get_rect().center[1] + 10,
        )
    # TODO: fix after WONDER_K img is ready
    # elif device == WONDER_K:
    #     rect.width -= 0
    #     rect.height -= 0
    #     rect.center = (
    #         screen.get_rect().center[0] - 0,
    #         screen.get_rect().center[1] + 0,
    #     )
    return rect
