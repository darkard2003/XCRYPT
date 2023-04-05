import os
from cryptography.fernet import Fernet, InvalidToken
import hashlib
import base64

HASH_FILE = ".keyHash"


def getKey(password: str):
    hashed = hashlib.sha256(password.encode()).digest()
    key = base64.b64encode(hashed)
    return key


def storeKeyHash(key: bytes, filePath: str):
    finalPath = os.path.join(filePath, HASH_FILE)
    keyHash = hashlib.sha256(key).digest()
    with open(finalPath, "wb") as file:
        file.write(keyHash)


def removeKeyHash(filePath: str):
    finalPath = os.path.join(filePath, HASH_FILE)
    if os.path.exists(finalPath):
        os.remove(finalPath)


def getHash(filePath: str):
    contents = os.listdir(filePath)
    if HASH_FILE not in contents:
        return None
    finalPath = os.path.join(filePath, HASH_FILE)
    keyHash = b""
    with open(finalPath, "rb") as file:
        keyHash = file.read()

    return keyHash


class Cypher:
    def __init__(self, password: str):
        self.key = getKey(password)
        self._cypher = Fernet(self.key)
        self._encryptedFiles = []
        self._ignore_list = [".keyHash", ".encryptedFiles"]

    def encryptFile(self, inputFile: str, outputFile: str):
        with open(inputFile, "rb") as file_content:
            content = file_content.read()
            outputContent = self._cypher.encrypt(content)

            with open(outputFile, "wb") as output:
                output.write(outputContent)

    def decryptFile(self, inputFile: str, outputFile: str):
        with open(inputFile, "rb") as file_content:
            content = file_content.read()
            try:
                outputContent = self._cypher.decrypt(content)
            except InvalidToken:
                raise WrongPasswordException

            with open(outputFile, "wb") as output:
                output.write(outputContent)

    def encryptFileName(self, fileName: str):
        fileName = fileName.encode()
        outputName = self._cypher.encrypt(fileName)
        outputName = base64.b64encode(outputName).decode()
        return outputName

    def decryptFileName(self, fileName: str):
        fileName = fileName.encode()
        outputName = base64.b64decode(fileName)
        try:
            outputName = self._cypher.decrypt(outputName)
        except InvalidToken:
            raise WrongPasswordException
        return outputName

    def encryptFolder(self, inputFolder: str, isSubFolder: bool = False):
        inputFolder = os.path.abspath(inputFolder)
        contents = os.listdir(inputFolder)
        if not isSubFolder:
            hashfile = getHash(inputFolder)
            if hashfile:
                if hashfile != hashlib.sha256(self.key).digest():
                    raise WrongPasswordException
            else:
                storeKeyHash(self.key, inputFolder)
            self.getEncryptedFileList(inputFolder)

        for content in contents:
            contentPath = os.path.join(inputFolder, content)

            if os.path.isdir(contentPath):
                self.encryptFolder(contentPath, isSubFolder=True)
                continue

            if content in self._ignore_list + self._encryptedFiles:
                continue

            outputName = self.encryptFileName(content)
            outputPath = os.path.join(inputFolder, outputName)
            self.encryptFile(contentPath, outputPath)
            self._encryptedFiles.append(outputName)
            os.remove(contentPath)

        if not isSubFolder:
            self.saveEncryptedFileList(inputFolder)

    def decryptFolder(self, inputFolder: str, isSubFolder: bool = False):
        contents = os.listdir(inputFolder)
        if not isSubFolder:
            hashFile = getHash(inputFolder)
            if hashFile:
                if hashFile != hashlib.sha256(self.key).digest():
                    raise WrongPasswordException
            self.getEncryptedFileList(inputFolder)

        for content in contents:
            contentPath = os.path.join(inputFolder, content)

            if os.path.isdir(contentPath):
                self.decryptFolder(contentPath, isSubFolder=True)
                continue

            if content not in self._encryptedFiles:
                continue

            outputName = self.decryptFileName(content).decode()
            outPutPath = os.path.join(inputFolder, outputName)
            self.decryptFile(contentPath, outPutPath)
            self._encryptedFiles.remove(content)

            os.remove(contentPath)

        removeKeyHash(inputFolder)

        if not isSubFolder:
            self.saveEncryptedFileList(inputFolder)

    def saveEncryptedFileList(self, filePath: str):
        filePath = os.path.join(filePath, ".encryptedFiles")
        with open(filePath, "w") as file:
            for encryptedFile in self._encryptedFiles:
                file.write(encryptedFile + "\n")

    def getEncryptedFileList(self, filePath: str):
        fileName = os.path.join(filePath, ".encryptedFiles")
        if not os.path.exists(fileName):
            return

        filePath = os.path.join(filePath, ".encryptedFiles")
        with open(filePath, "r") as file:
            for line in file:
                self._encryptedFiles.append(line.strip())

        return


class WrongPasswordException(InvalidToken):
    pass
