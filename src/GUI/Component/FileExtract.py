import flet as ft
from src.Proccess import Steganography
from src.Proccess.FileManagement import Secrets
from . import FileStego, FileCrypto

EXTRACT_STATUS = {
    0: 'Data is Empty.',
    1: 'Integrity check FAILED: hidden image was altered. File is not saved.',
    2: 'Extracted Failed: ',
    3: 'Extracted. SHA3-256 integrity check PASSED.',
    4: 'Extracted, but no SHA3-256 hash found.'
}


class FileExtractPanel:
    def __init__(self, page: ft.Page):
        self.page = page
        self.operations = FileExtractOperations(self.page, self)
        self.file_picker = {
            'input': self.init_file_picker('input'),
            'output': self.init_file_picker('output')
        }
        self.init_file_pickers()

        self.file_selector = {
            'input': self.init_file_selector('input'),
            'output': self.init_file_selector('output')
        }
        self.config_btn = self.init_config_btn()
        self.crypto_btn = self.init_crypto_btn()
        self.execute_btn = self.init_execute_btn()
        self.layout = self.init_layout()
        self.tab = self.init_tab()

    def init_file_text(self, _file_text: str):
        return ft.Text(_file_text, width=300, no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS)

    def init_file_picker(self, _file_type: str):
        filePicker = ft.FilePicker()
        filePicker.on_result = self.operations[_file_type]
        return filePicker

    def init_file_pickers(self):
        for picker in self.file_picker.values():
            self.page.overlay.extend([picker])
        self.page.update()

    def init_file_selector(self, _file_type: str):
        def pick_file(e):
            if _file_type == 'input':
                self.file_picker[_file_type].pick_files(allow_multiple=False)
            elif _file_type == 'output':
                self.file_picker[_file_type].save_file(
                    dialog_title='Save',
                    file_name='extract_output.png',
                    file_type=ft.FilePickerFileType.IMAGE
                )

        return ft.Row(
            controls=[
                ft.Button(f"{_file_type.upper()}", on_click=pick_file, width=150),
                ft.Text("Selected: ", size=14),
                self.init_file_text('None')
            ],
            alignment=ft.MainAxisAlignment.CENTER
        )

    def init_config_btn(self):
        return ft.IconButton(
            icon=ft.Icons.SETTINGS,
            on_click=lambda e: FileStego.FileStegoDialog(self.page).operations.open_dialog(e)
        )

    def init_crypto_btn(self):
        return ft.IconButton(
            icon=ft.Icons.KEY,
            on_click=lambda e: FileCrypto.FileCryptoDialog(self.page).operations.open_dialog(e)
        )

    def init_execute_btn(self):
        return ft.Button(
            text='Extract',
            on_click=self.operations['execute']
        )

    def init_layout(self):
        return ft.Column(
            controls=[
                self.file_selector['input'],
                self.file_selector['output'],
                ft.Row(
                    controls=[self.execute_btn, self.config_btn, self.crypto_btn],
                    alignment=ft.MainAxisAlignment.CENTER,
                    expand=False
                )
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=20
        )

    @staticmethod
    def init_tab():
        return ft.Tab('Extract')

    def update_file_text(self, _file_type: str, _file_text: str):
        self.file_selector[_file_type].controls[2] = self.init_file_text(_file_text)


class FileExtractOperations:
    def __init__(self, page: ft.Page, panel: FileExtractPanel):
        self.page = page
        self.panel = panel
        self.file_path = {
            'input': '',
            'output': ''
        }
        self.operations = {
            'input': lambda e: self.on_file_result(e, 'input'),
            'output': lambda e: self.on_file_result(e, 'output'),
            'execute': lambda e: self.on_execute(e)
        }

    def __getitem__(self, key):
        return self.operations[key]

    def on_file_result(self, e: ft.FilePickerResultEvent, _file_type: str):
        if e.files:
            self.file_path[_file_type] = e.files[0].path
            self.panel.update_file_text(_file_type, str(e.files[0].name))
        elif _file_type == 'output':
            self.file_path[_file_type] = e.path
            self.panel.update_file_text(_file_type, str(e.path))
        else:
            self.file_path[_file_type] = ''
            self.panel.update_file_text(_file_type, 'None')
        self.page.update()

    def on_execute(self, e):
        for path in self.file_path.values():
            if path is None or path == '':
                self.page.open(ft.SnackBar(ft.Text('Incomplete Paths')))
                return

        stego_config = FileStego.FileStegoDialog(self.page).operations.get_config()
        crypto_config = FileCrypto.FileCryptoDialog(self.page).operations.get_config()
        key = Secrets.derive_key(crypto_config['password']) if crypto_config['password'] else None

        stego = Steganography.Steganography(
            algorithm=stego_config['algorithm'],
            encryption={
                'algorithm': crypto_config['algorithm'],
                'mode': crypto_config['mode'],
                'params': crypto_config['params']
            },
            parameters=stego_config['params'],
            key=key
        )
        try:
            status, info = stego.extract_file(self.file_path['input'], self.file_path['output'])
            if status in EXTRACT_STATUS.keys():
                self.page.open(ft.SnackBar(ft.Text(f'{EXTRACT_STATUS[status]}{info}')))
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.page.open(ft.SnackBar(ft.Text(f'Error: {e}')))
