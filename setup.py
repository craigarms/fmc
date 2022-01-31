from setuptools import setup
setup(
    name="fmcutils",
    version="0.0.1",
    entry_point={
        'console_scripts': [
            'fmc=fmc:main'
        ]
    }
)