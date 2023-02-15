from setuptools import setup, find_packages


setup(
    name="PfSense_Dashboard-Frontend",
    version="1.0.x",
    author="Cameron Trippick",
    packages=['frontend', 'frontend.lib', 'frontend.blueprints', 'password_hasher'],
    include_package_data=True,
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'PfSense_Dashboard-Frontend = frontend.app:main',
            'PfSense_Dashboard-Password_Hasher = password_hasher.app:main'
        ]
    }
)