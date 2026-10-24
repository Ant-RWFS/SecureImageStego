import flet as ft
from src.GUI.MainWindow import MainWindow
import sys, socket, asyncio

if sys.platform == "win32":
    from asyncio import proactor_events

    _original = proactor_events._ProactorBasePipeTransport._call_connection_lost


    def _patched(self, exc):
        if isinstance(exc, ConnectionResetError):
            exc = None
        try:
            return _original(self, exc)
        except ConnectionResetError:
            pass


    proactor_events._ProactorBasePipeTransport._call_connection_lost = _patched


def main(page: ft.Page):
    window = MainWindow(page)


if __name__ == '__main__':
    ft.app(main)
