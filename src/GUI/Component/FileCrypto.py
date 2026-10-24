import flet as ft
from src.Proccess import Cryptography


class FileCryptoDialog(ft.AlertDialog):
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
            self.operations = FileCryptoOperation(self.page, self)
            self.algorithm_configs = self.init_algorithm_configs()
            self.mode_configs = self.init_mode_configs()
            self.password_field = self.init_password_field()
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
                ft.Text('Cryptography Config'),
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
            options=[ft.dropdown.Option(name) for name in Cryptography.CRYPTOGRAPHY.keys()],
            value='AES',
            on_change=lambda e: self.operations.on_algorithm_change(e)
        )

    def init_mode_configs(self):
        return ft.Dropdown(
            label='Mode',
            options=[ft.dropdown.Option(mode) for mode in Cryptography.CRYPTOGRAPHY['AES'].keys()],
            value='CTR',
            on_change=lambda e: self.operations.on_mode_change(e)
        )

    def init_password_field(self):
        return ft.TextField(
            label='Password',
            password=True,
            can_reveal_password=True,
            width=200
        )

    def init_configs(self):
        return ft.Column(
            controls=[
                self.algorithm_configs,
                self.mode_configs
            ],
            expand=True
        )

    def init_content(self, _algorithm=None, _mode=None):
        if _algorithm is None:
            _algorithm = self.algorithm_configs.value

        modes = list(Cryptography.CRYPTOGRAPHY[_algorithm].keys())
        if _mode is None:
            _mode = modes[0]

        self.mode_configs.options = [ft.dropdown.Option(mode) for mode in modes]
        self.mode_configs.value = _mode
        self.build_parameter_controls(_algorithm, _mode)

        param_column = ft.Column(
            controls=list(self.param_controls.values()),
            spacing=10
        )

        return ft.Container(
            content=ft.Column(
                controls=[
                    self.algorithm_configs,
                    self.mode_configs,
                    self.password_field,
                    param_column
                ],
                spacing=15,
            )
        )

    def build_parameter_controls(self, _algorithm, _mode):
        self.param_controls = {}
        param_defines = Cryptography.CRYPTOGRAPHY[_algorithm][_mode]['params']
        for param in param_defines:
            if param.param_type == int:
                control = ft.TextField(
                    label=param.label,
                    value=str(param.default),
                    input_filter=ft.NumbersOnlyInputFilter(),
                    width=200
                )
            elif param.param_type == float:
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

    def update_content(self, _algorithm=None, _mode=None):
        return self.init_content(_algorithm, _mode)


class FileCryptoOperation:
    def __init__(self, page: ft.Page, dialog: FileCryptoDialog):
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
        self.dialog.content = self.dialog.update_content(_algorithm=algorithm)
        self.page.update()

    def on_mode_change(self, e: ft.ControlEvent):
        mode = e.data
        self.dialog.content = self.dialog.update_content(_mode=mode)
        self.page.update()

    def get_config(self):
        config = {
            'algorithm': self.dialog.algorithm_configs.value,
            'mode': self.dialog.mode_configs.value,
            'params': {
                name: c.value
                for name, c in self.dialog.param_controls.items()
                if isinstance(c, ft.TextField)
            },
            'password': self.dialog.password_field.value or ''
        }
        for name, control in self.dialog.param_controls.items():
            if isinstance(control, ft.TextField):
                config['params'][name] = control.value
        return config
