#!/usr/bin/env python3

import setuptools

with open("README.md") as readme:
    long_description = readme.read()

setuptools.setup(
    name="certificate_watcher",
    version="0.0.3",
    description="Watch expiration of certificates of a bunch of websites.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Julien Palard",
    author_email="julien@palard.fr",
    url="https://github.com/JulienPalard/certificate_watcher",
    py_modules=["certificate_watcher"],
    entry_points={"console_scripts": ["certificate_watcher=certificate_watcher:main"]},
    license="MIT license",
    keywords="ssl tls certificate https watch sysadmin cron",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
)
