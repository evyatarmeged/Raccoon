from setuptools import setup

setup(
    name='raccoon-scanner',
    packages=['raccoon'],
    license='MIT',
    version='0.1',
    description='Offensive Security Tool for Reconnaissance and Information Gathering',
    author='Evyatar Meged',
    author_email='evyatarmeged@gmail.com',
    url='https://github.com/evyatarmeged/Raccoon',
    install_requires=['beautifulsoup4', 'requests', 'dnspython', "lxml", "click", "fake-useragent"],
    entry_points={
        'console_scripts': [
            'raccoon=raccoon.raccoon:main'
        ]
    },
)
