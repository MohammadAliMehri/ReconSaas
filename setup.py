from setuptools import setup, find_packages

setup(
    name="recon-framework",
    version="2.0.0",
    author="MohammadAliMehri",
    description="Zero-cost CLI reconnaissance framework with Passive, Active, and Hybrid modes",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/MohammadAliMehri/ReconSaas",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "httpx>=0.27.0",
        "dnspython>=2.6.0",
        "rich>=13.0.0",
        "pyyaml>=6.0",
        "tldextract>=5.1.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=5.1.0",
        "aiofiles>=23.2.0",
        "python-whois>=0.9.4",
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "recon=recon_framework.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)
