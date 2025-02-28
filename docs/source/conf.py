# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

from kaititu import __version__

project = 'KAITITU'
copyright = '2025, Silverlayer'
author = 'Kelvin S. Amorim'
version = __version__
release = 'v'+__version__

rst_epilog = f".. |project| replace:: {project}"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = ['sphinx.ext.autodoc','sphinx.ext.autosummary','sphinx.ext.napoleon']
napoleon_numpy_docstring = False
napoleon_include_special_with_doc = False
autodoc_class_signature = 'separated'
autodoc_typehints_format = 'fully-qualified'
napoleon_use_rtype = False
autodoc_default_options = {
    'show-inheritance': True,
    'special-members': '__init__',
    'members': True
}

templates_path = ['_templates']
exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'furo'
html_static_path = ['_static']
