"""Decorative, non-essential widgets for the dashboard."""

from __future__ import annotations

import math

from rich.text import Text
from textual.reactive import reactive
from textual.widgets import Static

ORBIT_W = 33
ORBIT_H = 13
TRAIL_LEN = 6
FPS = 10
ANGULAR_SPEED = 0.11  # radians per tick


class SatelliteOrbit(Static):
    """A small ASCII satellite tracking an elliptical orbit around a globe,
    purely decorative — gives the dashboard a 'live ops console' feel.
    """

    angle: reactive[float] = reactive(0.0)

    def on_mount(self) -> None:
        self.set_interval(1 / FPS, self._tick)
        self._render_frame()

    def _tick(self) -> None:
        self.angle = (self.angle + ANGULAR_SPEED) % (2 * math.pi)

    def watch_angle(self, _angle: float) -> None:
        self._render_frame()

    def _render_frame(self) -> None:
        cx, cy = ORBIT_W // 2, ORBIT_H // 2
        rx, ry = cx - 2, cy - 2

        grid: list[list[str]] = [[" "] * ORBIT_W for _ in range(ORBIT_H)]
        styles: list[list[str]] = [[""] * ORBIT_W for _ in range(ORBIT_H)]

        # faint orbit path
        for deg in range(0, 360, 5):
            rad = math.radians(deg)
            x = round(cx + rx * math.cos(rad))
            y = round(cy + ry * 0.45 * math.sin(rad))
            if 0 <= x < ORBIT_W and 0 <= y < ORBIT_H:
                grid[y][x] = "·"
                styles[y][x] = "grey37"

        # globe at center
        globe_rows = [" .-\"\"\"-. ", "/         \\", "|  OBSERVER |", "\\         /", " '-...-' "]
        gy0 = cy - len(globe_rows) // 2
        for i, row in enumerate(globe_rows):
            gy = gy0 + i
            if not (0 <= gy < ORBIT_H):
                continue
            gx0 = cx - len(row) // 2
            for j, ch in enumerate(row):
                gx = gx0 + j
                if ch != " " and 0 <= gx < ORBIT_W:
                    grid[gy][gx] = ch
                    styles[gy][gx] = "steel_blue"

        # satellite + fading trail
        for i in range(TRAIL_LEN, -1, -1):
            a = self.angle - i * 0.22
            x = round(cx + rx * math.cos(a))
            y = round(cy + ry * 0.45 * math.sin(a))
            if not (0 <= x < ORBIT_W and 0 <= y < ORBIT_H):
                continue
            if i == 0:
                grid[y][x] = "◆"  # ◆ satellite head
                styles[y][x] = "bold bright_cyan"
            else:
                grid[y][x] = "•"  # •
                fade = max(0, 4 - i // 2)
                styles[y][x] = ["bright_cyan", "cyan", "cyan", "dark_cyan", "grey50"][min(fade, 4)]

        text = Text()
        for y in range(ORBIT_H):
            for x in range(ORBIT_W):
                ch = grid[y][x]
                style = styles[y][x] or "grey23"
                text.append(ch, style=style)
            if y != ORBIT_H - 1:
                text.append("\n")
        self.update(text)
