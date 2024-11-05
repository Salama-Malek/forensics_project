# analysis/templatetags/custom_filters.py
import os

from django import template
register = template.Library()


# @register.filter(name='add_class')
# def add_class(field, css):
#     return field.as_widget(attrs={"class": css})

@register.filter
def file_extension(value):
    """Returns the file extension of the file path, including the dot."""
    return os.path.splitext(value)[1]


@register.filter
def endswith(value, arg):
    """Returns True if the value ends with the argument string."""
    return str(value).lower().endswith(arg)

@register.filter
def basename(value):
    """Returns the base name of the file path (including the extension)."""
    return os.path.basename(value)

@register.filter
def shorten_filename(value, length=20):
    """Shortens the file name while keeping the extension intact."""
    basename = os.path.basename(value)
    name, ext = os.path.splitext(basename)
    if len(name) > length:
        name = name[:length] + "..."
    return f"{name}{ext}"