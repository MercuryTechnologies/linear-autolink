import setuptools

setuptools.setup(
    name = 'linear_autolink',
    version = '0.0.1',
    py_modules = ['linear_autolink'],
    python_requires = '>=3.8',
    install_requires = ['requests', 'pyjwt', 'cryptography'],
    description = 'Script to create GitHub autolinks from Linear teams',
    entry_points = {
        'console_scripts': [
            'linear-autolink=linear_autolink:main'
        ]
    },
    license = 'MIT',
    url = 'https://github.com/MercuryTechnologies/linear-autolink'
)
