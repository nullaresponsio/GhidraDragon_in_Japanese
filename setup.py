from setuptools import setup, Extension
import pybind11
import os

# Ensure src directory exists
here = os.path.abspath(os.path.dirname(__file__))
src_dir = os.path.join(here, "src")

ext = Extension(
    "softtpm_py",
    [os.path.join(src_dir, "softtpm.cpp"), os.path.join(src_dir, "binding.cpp")],
    include_dirs=[pybind11.get_include(), src_dir],
    libraries=["crypto"],
    extra_compile_args=["-std=c++17"],
)

setup(
    name="softtpm",
    version="0.1.0",
    ext_modules=[ext],
)
