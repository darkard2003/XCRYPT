import os.path
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QLineEdit, QErrorMessage, QMessageBox
from PyQt5 import QtGui
from PyQt5 import QtCore
from utils.encryption import Cypher, WrongPasswordException

from gui.mainui import Ui_MainWindow


class EncryptionWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.mainUI = Ui_MainWindow()
        self.errDialog = QErrorMessage()
        self.initUI()
        self.encryption_folder = os.path.curdir

    def initUI(self):
        self.mainUI.setupUi(self)

        self.setGeometry(300, 300, 720, 480)

        self.errDialog.setWindowTitle("Wrong password")
        self.errDialog.setWindowIcon(QtGui.QIcon(".\\assets\\lock.ico"))

        self.mainUI.lockImage.setPixmap(QtGui.QPixmap('.\\assets\\lock.png'))
        self.mainUI.lockImage.setAlignment(QtCore.Qt.AlignCenter)

        self.mainUI.passwordInput.setEchoMode(QLineEdit.Password)

        self.mainUI.encryptButton.clicked.connect(self.encryptCurrentFolder)
        self.mainUI.decryptButton.clicked.connect(self.decryptCurrentFolder)

    def encryptCurrentFolder(self):
        password = self.mainUI.passwordInput.text()

        if len(password) == 0:
            return

        if len(password) < 8:
            self.errDialog.showMessage("Password must be at least 8 characters long")
            return

        self.mainUI.passwordInput.clear()

        current_folder = os.path.basename(os.path.abspath(self.encryption_folder))

        encryption_choice = QMessageBox.question(self, "Encryption", f"Do you want to encrypt {current_folder}?",
                                                 QMessageBox.Yes | QMessageBox.No)

        if encryption_choice == QMessageBox.No:
            return

        cypher = Cypher(password)
        try:
            cypher.encryptFolder(self.encryption_folder)
        except WrongPasswordException:
            self.errDialog.showMessage("Wrong password")

    def decryptCurrentFolder(self):
        password = self.mainUI.passwordInput.text()
        self.mainUI.passwordInput.clear()
        cypher = Cypher(password)
        try:
            cypher.decryptFolder(self.encryption_folder)
        except WrongPasswordException:
            self.errDialog.showMessage("Wrong password")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EncryptionWindow()
    window.show()
    sys.exit(app.exec_())
