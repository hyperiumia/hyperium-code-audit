from setuptools import setup, find_packages
setup(
    name="hyperium-code-audit",
    version="4.0.0",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=["click>=8.0", "rich>=13.0", "pydantic>=2.0", "pyyaml>=6.0"],
    entry_points={"console_scripts": ["code-audit=src.cli:main"]},
)
