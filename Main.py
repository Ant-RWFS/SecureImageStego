import flet as ft
from src.GUI.MainWindow import MainWindow


def main(page: ft.Page):
    window = MainWindow(page)


if __name__ == '__main__':
    ft.app(main)
