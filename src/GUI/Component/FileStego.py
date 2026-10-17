import flet as ft

from src.Proccess import Steganography


class FileStegoDialog(ft.AlertDialog):
    instance = None
    initialized = False

    def __new__(cls, *args, **kwargs):
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    def __init__(self, page: ft.Page, **kwargs):
        if not self.initialized:
            super().__init__(**kwargs)
            self.page = page
            self.title = self.init_title()
            self.operations = FileStegoOperation(self.page, self)
            self.algorithm_configs = self.init_algorithm_configs()
            self.param_controls = {}
            self.configs = self.init_configs()
            self.content = self.init_content()
            self.page.update()
            self.initialized = True
        else:
            self.page = page

    def init_title(self):
        return ft.Row(
            controls=[
                ft.Text('Steganography Config'),
                ft.IconButton(
                    icon=ft.Icons.CLOSE,
                    on_click=lambda e: self.operations.close_dialog(e),
                )
            ],
            alignment=ft.MainAxisAlignment.END
        )

    def init_algorithm_configs(self):
        return ft.Dropdown(
            label='Algorithm',
            options=[ft.dropdown.Option(name) for name in Steganography.STEGANOGRAPHY.keys()],
            value='LSB',
            on_change=lambda e: self.operations.on_algorithm_change(e)
        )

    def init_configs(self):
        return ft.Column(
            controls=[
                self.algorithm_configs
            ],
            expand=True
        )

    def build_parameter_controls(self, _algorithm):
        self.param_controls = {}
        param_defines = Steganography.STEGANOGRAPHY[_algorithm]['params']
        for param in param_defines:
            if param.param_type is int:
                control = ft.TextField(
                    label=param.label,
                    value=str(param.default),
                    input_filter=ft.NumbersOnlyInputFilter(),
                    width=200
                )
            elif param.param_type is float:
                control = ft.TextField(
                    label=param.label,
                    value=str(param.default),
                    width=200
                )
            else:
                control = ft.TextField(
                    label=param.label,
                    value=str(param.default),
                    width=200
                )
            self.param_controls[param.name] = control

    def init_content(self, _algorithm='LSB'):
        self.build_parameter_controls(_algorithm)
        param_column = ft.Column(
            controls=list(self.param_controls.values()),
            spacing=10
        )

        return ft.Container(
            content=ft.Column(
                controls=[
                    self.algorithm_configs,
                    param_column
                ],
                spacing=15,
            )
        )

    def update_content(self, _algorithm):
        return self.init_content(_algorithm)


class FileStegoOperation:
    def __init__(self, page: ft.Page, dialog: FileStegoDialog):
        self.page = page
        self.dialog = dialog

    def close_dialog(self, e):
        self.page.close(self.dialog)
        self.page.update()

    def open_dialog(self, e):
        self.page.open(self.dialog)
        self.page.update()

    def on_algorithm_change(self, e: ft.ControlEvent):
        algorithm = e.data
        self.dialog.content = self.dialog.update_content(algorithm)
        self.page.update()

    def get_config(self):
        config = {
            'algorithm': self.dialog.algorithm_configs.value,
            'params': {}
        }
        for name, control in self.dialog.param_controls.items():
            if isinstance(control, ft.TextField):
                config['params'][name] = control.value
        return config
