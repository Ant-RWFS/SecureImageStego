import flet as ft
from src.GUI.Component import FileEmbed, FileExtract


class MainWindow:
    def __init__(self, page: ft.Page):
        self.page = None
        self.init_page(page)
        self.embed_panel = FileEmbed.FileEmbedPanel(page)
        self.extract_panel = FileExtract.FileExtractPanel(page)
        self.layout = self.init_layout()
        page.add(self.layout)

    def init_page(self, page: ft.Page):
        self.page = page
        self.page.vertical_alignment = ft.MainAxisAlignment.CENTER
        self.page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
        self.page.window_width = 700
        self.page.window_height = 400

    def init_layout(self):
        tabs = [self.embed_panel.tab, self.extract_panel.tab]
        panels = [self.embed_panel.layout, self.extract_panel.layout]

        for control in panels:
            if control is panels[0]:
                control.visible = True
            else:
                control.visible = False

        self.embed_panel.layout.visible = True
        self.extract_panel.layout.visible = False
        return ft.Column(
            controls=[
                ft.Tabs(
                    tabs=tabs,
                    on_change=lambda e: self.switch_tab(e, panels),
                    expand=False
                ),
                ft.Stack(
                    controls=panels,
                    expand=True
                )
            ],
            expand=True
        )

    def switch_tab(self, e: ft.ControlEvent, panels):
        for panel in panels:
            if panel is not panels[int(e.data)]:
                panel.visible = False
            else:
                panel.visible = True
        self.page.update()


class MainWindowOperation:
    def __init__(self, page: ft.Page, window: MainWindow):
        self.page = page
        self.window = window

    # def
