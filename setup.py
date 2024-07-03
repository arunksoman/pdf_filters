from setuptools import setup, Extension

# Define the Cython extensions
extensions = [
    Extension("pdf_filters.ccitt", sources=["src/pdf_filters/ccitt.pyx"]),
    # Extension("pdf_filters.ascii85", sources=["src/pdf_filters/ascii85.pyx"]),
    # Extension("pdf_filters.lzw", sources=["src/pdf_filters/lzw.pyx"]),
]

setup(
    name="pdf_filters",
    version="0.1.0",  # Change this to your desired version
    description="PDF filter implementations in Cython",
    author="Your Name",
    author_email="arun@stackquest.in",
    packages=["pdf_filters"],  # The package name
    ext_modules=extensions,
    # Add any additional dependencies your project requires
    # install_requires=[],
)
