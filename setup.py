"""Setup configuration for prototype-pollution-detector."""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="prototype-pollution-detector",
    version="0.1.0",
    author="Letao Zhao, Ethan Lee, Bingyan He, Qi Sun",
    description="A tool for detecting client-side prototype pollution vulnerabilities in JavaScript code",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/TinkAnet/Prototype-pollution-detection",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        # Add dependencies here as needed
        # Example: "esprima>=4.0.1",  # For JavaScript parsing
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=23.0",
            "flake8>=6.0",
            "mypy>=1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "prototype-pollution-detector=prototype_pollution_detector.cli:main",
        ],
    },
)
